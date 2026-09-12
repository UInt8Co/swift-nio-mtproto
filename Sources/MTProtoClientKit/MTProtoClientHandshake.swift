import Crypto
import MTProtoBaseSchema
import MTProtoCrypto
import NIOMTProtoEncryption
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Errors produced while running the client side of the auth-key handshake.
public enum MTProtoClientHandshakeError: Error, Equatable {
  /// A message body started with a constructor the handshake doesn't know.
  case unexpectedConstructor(UInt32)
  /// A message arrived for a handshake phase that hasn't been reached.
  case unexpectedMessage
  /// The server echoed a `nonce` / `server_nonce` we didn't issue.
  case nonceMismatch
  /// `resPQ.server_public_key_fingerprints` did not offer the trusted key —
  /// the peer is not the server whose RSA key we were configured with.
  case fingerprintNotOffered([Int64])
  /// The server's `pq` challenge was not a factorable ~62-bit semiprime.
  case pqUnfactorable(UInt64)
  /// `pq` was not an unsigned integer encoded in at most eight bytes.
  case invalidPQ
  /// The server answered `server_DH_params_fail`.
  case serverDHParamsFailed
  /// The SHA-1 integrity prefix of `server_DH_inner_data` didn't match.
  case innerHashMismatch
  /// The server offered a DH group other than the trusted one.
  case unexpectedDHParameters
  /// The server's `g_a` was outside the safe range
  /// `2^{2048-64} < g_a < p − 2^{2048-64}`.
  case invalidServerPublicValue
  /// The server answered `dh_gen_retry` / `dh_gen_fail`.
  case dhGenFailed
  /// `dh_gen_ok.new_nonce_hash1` didn't match the negotiated key.
  case newNonceHashMismatch
}

/// The client side of the MTProto auth-key handshake
/// (<https://core.telegram.org/mtproto/auth_key>), as a synchronous state
/// machine over *plaintext message bodies* (the `auth_key_id = 0` envelope is
/// handled by ``MTProtoClientSessionCrypto``):
///
/// ```
/// req_pq_multi          → resPQ
/// req_DH_params         → server_DH_params_ok
/// set_client_DH_params  → dh_gen_ok  (+ established session keys)
/// ```
///
/// The handshake authenticates the server: the client checks the offered RSA
/// fingerprint against the trusted public key, RSA-encrypts `p_q_inner_data` to
/// that key (RSA_PAD layout), and only the holder of the matching private key
/// can complete DH.
public struct MTProtoClientHandshake: Sendable {
  /// The outcome of processing one handshake message.
  public enum Result: Sendable {
    /// Send this message body to the server (in a plaintext envelope).
    case send(Data)
    /// The handshake completed: the negotiated session keys.
    case established(MTProtoSessionKeys)
  }

  private enum State {
    /// ``start()`` not called yet.
    case initial
    /// `req_pq_multi` sent; waiting for `resPQ`.
    case sentReqPQ
    /// `req_DH_params` sent; waiting for `server_DH_params_ok`.
    case sentDHParams
    /// `set_client_DH_params` sent; waiting for `dh_gen_ok`.
    case sentClientDH(authKey: Data, serverSalt: Int64)
    case established
  }

  private let rsaKey: RSAPublicKey
  private let dh: MTProtoDHParameters
  /// The DC id to embed in `p_q_inner_data_dc`; nil sends the plain
  /// (dc-less) `p_q_inner_data` constructor.
  private let dcID: Int32?
  private let nonce = TLInt128.random()
  private let newNonce = TLInt256.random()
  private var serverNonce: TLInt128 = .zero
  private var state: State = .initial

  /// `server_time − local_time`, learned from `server_DH_inner_data`. Feed
  /// it to the session's `msg_id` generator so ids stay inside the server's
  /// acceptance window even with clock skew.
  public private(set) var serverTimeOffset: Int64 = 0

  public init(
    rsaKey: RSAPublicKey,
    dhParameters: MTProtoDHParameters = .telegram2048,
    dcID: Int32? = nil
  ) {
    self.rsaKey = rsaKey
    self.dh = dhParameters
    self.dcID = dcID
  }

  /// Begins the handshake, returning the `req_pq_multi` body to send.
  public mutating func start() -> Data {
    state = .sentReqPQ
    return TL.ReqPqMulti(nonce: nonce).tlSerialized()
  }

  /// Processes one plaintext handshake reply body.
  public mutating func process(messageBody: Data) throws -> Result {
    var reader = TLReader(messageBody)
    let constructorID = try reader.peekUInt32()
    switch constructorID {
    case TL.ResPQ.tlConstructorID:
      return .send(try handleResPQ(TL.ResPQ(tlFrom: &reader)))
    case TL.ServerDHParamsOk.tlConstructorID, TL.ServerDHParamsFail.tlConstructorID:
      return .send(try handleServerDHParams(TL.ServerDHParamsType(tlFrom: &reader)))
    case TL.DhGenOk.tlConstructorID, TL.DhGenRetry.tlConstructorID,
      TL.DhGenFail.tlConstructorID:
      return .established(
        try handleDHGenAnswer(TL.SetClientDHParamsAnswerType(tlFrom: &reader)))
    default:
      throw MTProtoClientHandshakeError.unexpectedConstructor(constructorID)
    }
  }

  // MARK: - resPQ → req_DH_params

  private mutating func handleResPQ(_ resPQ: TL.ResPQ) throws -> Data {
    guard case .sentReqPQ = state else {
      throw MTProtoClientHandshakeError.unexpectedMessage
    }
    guard resPQ.nonce == nonce else {
      throw MTProtoClientHandshakeError.nonceMismatch
    }
    // The peer must offer the RSA key the caller vouches for; only the holder
    // of that key's private half can then decrypt p_q_inner_data and finish DH.
    guard resPQ.serverPublicKeyFingerprints.contains(rsaKey.fingerprint) else {
      throw MTProtoClientHandshakeError.fingerprintNotOffered(
        resPQ.serverPublicKeyFingerprints)
    }
    serverNonce = resPQ.serverNonce

    // The proof-of-work: factor pq into p < q.
    // Do not truncate an oversized TL string to UInt64: the original bytes
    // also enter the fixed-size RSA_PAD block later in the handshake.
    guard !resPQ.pq.isEmpty, resPQ.pq.count <= 8 else {
      throw MTProtoClientHandshakeError.invalidPQ
    }
    let pq = resPQ.pq.reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
    guard let (p, q) = PQFactorization.factor(pq) else {
      throw MTProtoClientHandshakeError.pqUnfactorable(pq)
    }
    let pBytes = PQChallenge.factorBytes(p)
    let qBytes = PQChallenge.factorBytes(q)

    let inner: TL.PQInnerDataType
    if let dcID {
      inner = .pQInnerDataDc(
        TL.PQInnerDataDc(
          pq: resPQ.pq, p: pBytes, q: qBytes, nonce: nonce,
          serverNonce: serverNonce, newNonce: newNonce, dc: dcID))
    } else {
      inner = .pQInnerData(
        TL.PQInnerData(
          pq: resPQ.pq, p: pBytes, q: qBytes, nonce: nonce,
          serverNonce: serverNonce, newNonce: newNonce))
    }

    state = .sentDHParams
    return TL.ReqDHParams(
      nonce: nonce,
      serverNonce: serverNonce,
      p: pBytes,
      q: qBytes,
      publicKeyFingerprint: rsaKey.fingerprint,
      encryptedData: rsaKey.encryptRSAPad(inner.tlSerialized())
    ).tlSerialized()
  }

  // MARK: - server_DH_params_ok → set_client_DH_params

  private mutating func handleServerDHParams(
    _ answer: TL.ServerDHParamsType
  ) throws -> Data {
    guard case .sentDHParams = state else {
      throw MTProtoClientHandshakeError.unexpectedMessage
    }
    guard case .serverDHParamsOk(let ok) = answer else {
      throw MTProtoClientHandshakeError.serverDHParamsFailed
    }
    guard ok.nonce == nonce, ok.serverNonce == serverNonce else {
      throw MTProtoClientHandshakeError.nonceMismatch
    }

    let kdf = HandshakeKDF.tmpAESKeyIV(
      serverNonce: int128Data(serverNonce), newNonce: int256Data(newNonce))
    let answerData = try AESIGE.decrypt(ok.encryptedAnswer, key: kdf.key, iv: kdf.iv)
    guard answerData.count > 20 else {
      throw MTProtoClientHandshakeError.innerHashMismatch
    }
    let innerData = Data([UInt8](answerData)[20...])
    var innerReader = TLReader(innerData)
    let serverInner = try TL.ServerDHInnerData(tlFrom: &innerReader)
    let expectedHash = Array(
      Insecure.SHA1.hash(data: innerData.prefix(innerReader.offset)))
    guard Array(answerData.prefix(20)) == expectedHash else {
      throw MTProtoClientHandshakeError.innerHashMismatch
    }
    guard serverInner.nonce == nonce, serverInner.serverNonce == serverNonce else {
      throw MTProtoClientHandshakeError.nonceMismatch
    }
    // Trust only the configured group: matching the known-safe prime is how
    // real clients skip the expensive primality validation.
    guard serverInner.g == dh.g, serverInner.dhPrime == dh.primeBytes else {
      throw MTProtoClientHandshakeError.unexpectedDHParameters
    }
    serverTimeOffset =
      Int64(serverInner.serverTime) - Int64(Date().timeIntervalSince1970)

    let gA = BigUInt(bigEndianBytes: serverInner.gA)
    guard dh.isSafePublicValue(gA) else {
      throw MTProtoClientHandshakeError.invalidServerPublicValue
    }

    // Our DH contribution, retried until g_b lands in the safe range (the
    // same bound the server demands; practically never loops).
    var secret = dh.randomExponent()
    var gB = dh.publicValue(secret: secret)
    while !dh.isSafePublicValue(gB) {
      secret = dh.randomExponent()
      gB = dh.publicValue(secret: secret)
    }
    let authKey = dh.sharedSecret(peerPublic: gA, secret: secret)

    // server_salt = new_nonce[0..8] XOR server_nonce[0..8].
    let nn = int256Data(newNonce)
    let sn = int128Data(serverNonce)
    var saltBytes = [UInt8](repeating: 0, count: 8)
    for i in 0..<8 { saltBytes[i] = nn[nn.startIndex + i] ^ sn[sn.startIndex + i] }
    let serverSalt = saltBytes.withUnsafeBytes { $0.loadUnaligned(as: Int64.self) }

    let clientInner = TL.ClientDHInnerData(
      nonce: nonce, serverNonce: serverNonce, retryId: 0,
      gB: gB.bigEndianBytes()
    ).tlSerialized()
    // payload = SHA1(inner) ‖ inner, padded with random to a multiple of 16.
    var payload = Data(Insecure.SHA1.hash(data: clientInner))
    payload.append(clientInner)
    payload.append(randomData((16 - payload.count % 16) % 16))
    let encrypted = try AESIGE.encrypt(payload, key: kdf.key, iv: kdf.iv)

    state = .sentClientDH(authKey: authKey, serverSalt: serverSalt)
    return TL.SetClientDHParams(
      nonce: nonce, serverNonce: serverNonce, encryptedData: encrypted
    ).tlSerialized()
  }

  // MARK: - dh_gen_ok

  private mutating func handleDHGenAnswer(
    _ answer: TL.SetClientDHParamsAnswerType
  ) throws -> MTProtoSessionKeys {
    guard case .sentClientDH(let authKey, let serverSalt) = state else {
      throw MTProtoClientHandshakeError.unexpectedMessage
    }
    guard case .dhGenOk(let ok) = answer else {
      // Neither retry nor fail is recoverable here; both abort the handshake.
      throw MTProtoClientHandshakeError.dhGenFailed
    }
    guard ok.nonce == nonce, ok.serverNonce == serverNonce else {
      throw MTProtoClientHandshakeError.nonceMismatch
    }
    // new_nonce_hash1 = SHA1(new_nonce ‖ 0x01 ‖ SHA1(auth_key)[0..8])[4..20] —
    // proves the server derived the same key.
    var input = int256Data(newNonce)
    input.append(1)
    input.append(contentsOf: Array(Insecure.SHA1.hash(data: authKey)).prefix(8))
    let digest = Array(Insecure.SHA1.hash(data: input))
    var hashReader = TLReader(Array(digest[4..<20]))
    guard ok.newNonceHash1 == (try hashReader.readInt128()) else {
      throw MTProtoClientHandshakeError.newNonceHashMismatch
    }

    state = .established
    return MTProtoSessionKeys(
      authKey: authKey,
      authKeyID: MTProtoMessageCrypto.authKeyID(authKey),
      serverSalt: serverSalt)
  }
}
