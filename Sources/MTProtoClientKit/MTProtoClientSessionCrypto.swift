import MTProtoBaseSchema
import MTProtoCrypto
import NIOMTProtoEncryption
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Errors produced by the client session-crypto layer (outside the handshake).
public enum MTProtoClientSessionError: Error, Equatable {
  /// A payload was too short / malformed, an unexpected plaintext message
  /// arrived with no handshake running, or an encrypted message carried a
  /// session id other than ours.
  case badEnvelope
  /// `encrypt` was called before a session existed (no auth key yet).
  case noSession
  /// An encrypted payload referenced an auth key other than this session's.
  case wrongAuthKeyID(Int64)
  /// The client handshake state machine rejected a server reply. The
  /// connection should be torn down: the handshake cannot recover.
  case handshakeRejected(String)
}

/// All crypto state for one MTProto *client* connection: the plaintext auth-key
/// handshake, then the
/// MTProto 2.0 encrypted session (encode `.fromClient`, decode `.fromServer`),
/// plus the client-side `msg_id` (`≡ 0 (mod 4)`, monotonic, server-time
/// adjusted) and `seq_no` assignment.
///
/// A synchronous state machine over whole MTProto payloads (as delivered by
/// `NIOMTProtoTransport`); ``MTProtoClientConnection`` drives it and owns the
/// session *rules* (correlation, acks, salt adoption, resends).
public struct MTProtoClientSessionCrypto: Sendable {
  /// The outcome of processing one inbound payload.
  public enum Inbound: Sendable {
    /// A handshake exchange: write `payload` (already enveloped) back.
    case handshakeSend(Data)
    /// The handshake completed; an encrypted session (fresh session id) is
    /// now live. The caller should persist the keys.
    case established(MTProtoSessionKeys)
    /// One decrypted, authenticated MTProto message.
    case message(MTProtoPlainMessage)
    /// A transport-level protocol error frame (4-byte negative int), e.g.
    /// `-404` "auth key not found".
    case protocolError(Int32)
  }

  private var handshake: MTProtoClientHandshake
  private var handshakeActive = false

  // Established session state.
  private var authKey: Data?
  public private(set) var authKeyID: Int64 = 0
  public private(set) var serverSalt: Int64 = 0
  public private(set) var sessionID: Int64 = 0
  private var lastMsgID: UInt64 = 0
  private var contentSeqNo: Int32 = 0
  /// `server_time − local_time`, folded into generated `msg_id`s.
  public private(set) var timeOffset: Int64 = 0

  public init(
    rsaKey: RSAPublicKey,
    dhParameters: MTProtoDHParameters = .telegram2048,
    dcID: Int32? = nil
  ) {
    self.handshake = MTProtoClientHandshake(
      rsaKey: rsaKey, dhParameters: dhParameters, dcID: dcID)
  }

  /// Whether the connection holds an auth key (negotiated or resumed).
  public var hasSession: Bool { authKey != nil }

  /// Local unix time adjusted by the learned server-time offset — the `now`
  /// to validate inbound (server-stamped) `msg_id`s against.
  public var adjustedNow: Int64 {
    Int64(Date().timeIntervalSince1970) + timeOffset
  }

  /// Begins the auth-key handshake, returning the enveloped `req_pq_multi`
  /// payload to write.
  public mutating func startHandshake() -> Data {
    handshakeActive = true
    return plaintextEnvelope(handshake.start())
  }

  /// Installs a previously negotiated session (auth key + the salt stored
  /// with it), skipping the handshake. Starts a fresh session id — the
  /// server will answer the first message with `new_session_created`.
  public mutating func resumeSession(authKey: Data, serverSalt: Int64) {
    self.authKey = authKey
    self.authKeyID = MTProtoMessageCrypto.authKeyID(authKey)
    self.serverSalt = serverSalt
    startNewSession()
  }

  /// Adopts a server-supplied salt (`bad_server_salt.new_server_salt`,
  /// `new_session_created.server_salt`, or a `future_salts` entry).
  public mutating func adoptSalt(_ salt: Int64) {
    serverSalt = salt
  }

  /// Rotates to a fresh (random) session id and resets the content sequence
  /// counter — on resume, and on `bad_msg_notification` code 17.
  ///
  /// `lastMsgID` is also reset so the next `msg_id` reflects the *current*
  /// (possibly just-corrected) clock. Without this, `bad_msg_notification`
  /// code 17 recovery is a no-op: after `updateTimeOffset` lowers the clock,
  /// `nextMsgID`'s strict-monotonic clamp (`lastMsgID + 4`) would keep
  /// re-emitting an id near the rejected too-high one. Safe because every
  /// caller also starts a fresh session id, so monotonicity within a session
  /// is not violated.
  public mutating func startNewSession() {
    var rng = SystemRandomNumberGenerator()
    sessionID = Int64(bitPattern: rng.next())
    contentSeqNo = 0
    lastMsgID = 0
  }

  /// Re-anchors the server-time estimate from an authenticated server
  /// `msg_id` (its high 32 bits are the server's unix time).
  public mutating func updateTimeOffset(fromServerMsgID msgID: Int64) {
    let serverTime = Int64(UInt64(bitPattern: msgID) >> 32)
    timeOffset = serverTime - Int64(Date().timeIntervalSince1970)
  }

  // MARK: - Inbound

  /// Processes one inbound MTProto payload (plaintext, encrypted, or a
  /// transport error frame).
  public mutating func processInbound(_ payload: Data) throws -> Inbound {
    // A 4-byte frame is a transport-level protocol error (e.g. -404); a real
    // envelope is at least 8 (plaintext) / 24 (encrypted) bytes.
    if payload.count == 4 {
      var reader = TLReader(payload)
      return .protocolError(try reader.readInt32())
    }
    var reader = TLReader(payload)
    guard let envelopeKeyID = try? reader.readInt64() else {
      throw MTProtoClientSessionError.badEnvelope
    }
    if envelopeKeyID == 0 {
      return try processPlaintext(&reader)
    }
    guard let authKey, envelopeKeyID == authKeyID else {
      throw MTProtoClientSessionError.wrongAuthKeyID(envelopeKeyID)
    }
    let message = try MTProtoEncryptedMessage.decode(
      payload, authKey: authKey, direction: .fromServer)
    // The server always echoes the session id we sent; anything else is not
    // for this session.
    guard message.sessionID == sessionID else {
      throw MTProtoClientSessionError.badEnvelope
    }
    return .message(message)
  }

  private mutating func processPlaintext(_ reader: inout TLReader) throws -> Inbound {
    guard handshakeActive else { throw MTProtoClientSessionError.badEnvelope }
    _ = try reader.readInt64()  // server message_id
    let length = Int(try reader.readInt32())
    guard length >= 0, length <= reader.bytesRemaining else {
      throw MTProtoClientSessionError.badEnvelope
    }
    let body = try reader.readRawBytes(length)

    let result: MTProtoClientHandshake.Result
    do {
      result = try handshake.process(messageBody: body)
    } catch {
      // Unlike ordinary malformed traffic, a rejected handshake reply leaves
      // the client waiting forever; surface distinctly so the connection is
      // torn down.
      throw MTProtoClientSessionError.handshakeRejected(String(describing: error))
    }
    switch result {
    case .send(let next):
      return .handshakeSend(plaintextEnvelope(next))
    case .established(let keys):
      authKey = keys.authKey
      authKeyID = keys.authKeyID
      serverSalt = keys.serverSalt
      timeOffset = handshake.serverTimeOffset
      handshakeActive = false
      startNewSession()
      return .established(keys)
    }
  }

  /// Wraps a handshake message body in the unencrypted client envelope
  /// (`auth_key_id = 0`, `msg_id`, `length`).
  private mutating func plaintextEnvelope(_ body: Data) -> Data {
    var writer = TLWriter()
    writer.writeInt64(0)
    writer.writeInt64(nextMsgID())
    writer.writeInt32(Int32(body.count))
    writer.writeRawData(body)
    return writer.data
  }

  // MARK: - Outbound

  /// Encrypts one outbound message body, assigning the next client `msg_id`
  /// and `seq_no`. Returns the assigned id (the correlation key for
  /// `rpc_result` / `bad_msg_notification`) with the sealed payload.
  public mutating func encrypt(
    body: Data, contentRelated: Bool
  ) throws -> (msgID: Int64, payload: Data) {
    guard let authKey else { throw MTProtoClientSessionError.noSession }
    let msgID = nextMsgID()
    let payload = try MTProtoEncryptedMessage.encode(
      body: body, salt: serverSalt, sessionID: sessionID, msgID: msgID,
      seqNo: nextSeqNo(contentRelated: contentRelated),
      authKey: authKey, authKeyID: authKeyID, direction: .fromClient)
    return (msgID, payload)
  }

  /// Seals several messages as one `msg_container`. Each inner message gets
  /// its own `msg_id`/`seq_no` (assigned first, so the container's id is
  /// strictly greater, as required); the container itself is a service
  /// message. Returns the inner ids in argument order.
  public mutating func encryptContainer(
    _ messages: [(body: Data, contentRelated: Bool)]
  ) throws -> (msgIDs: [Int64], payload: Data) {
    guard authKey != nil else { throw MTProtoClientSessionError.noSession }
    var inner = TLWriter()
    inner.writeUInt32(MTProtoClientID.msgContainer)
    inner.writeInt32(Int32(messages.count))
    var msgIDs: [Int64] = []
    for message in messages {
      let msgID = nextMsgID()
      msgIDs.append(msgID)
      inner.writeInt64(msgID)
      inner.writeInt32(nextSeqNo(contentRelated: message.contentRelated))
      inner.writeInt32(Int32(message.body.count))
      inner.writeRawData(message.body)
    }
    let (_, payload) = try encrypt(body: inner.data, contentRelated: false)
    return (msgIDs, payload)
  }

  // MARK: - msg_id / seq_no

  /// The next client message id: server-time-based, strictly increasing, and
  /// `≡ 0 (mod 4)` as servers require of client messages.
  private mutating func nextMsgID() -> Int64 {
    let now = UInt64(bitPattern: Int64(Date().timeIntervalSince1970) + timeOffset)
    var candidate = now << 32
    if candidate <= lastMsgID { candidate = lastMsgID + 4 }
    candidate &= ~UInt64(3)
    if candidate <= lastMsgID { candidate += 4 }
    lastMsgID = candidate
    return Int64(bitPattern: candidate)
  }

  private mutating func nextSeqNo(contentRelated: Bool) -> Int32 {
    if contentRelated {
      let seqNo = contentSeqNo * 2 + 1
      contentSeqNo += 1
      return seqNo
    }
    return contentSeqNo * 2
  }
}

/// Constructor numbers for the low-level combinators the client session layer
/// handles directly. Generated types contribute their ids; only the framing
/// pseudo-combinators (`msg_container`, `gzip_packed`) need literals (the
/// generator skips them — they require length-delimited parsing).
enum MTProtoClientID {
  static let rpcResult = TL.RpcResult.tlConstructorID
  static let rpcError = TL.RpcError.tlConstructorID
  static let pong = TL.Pong.tlConstructorID
  static let badMsgNotification = TL.BadMsgNotification.tlConstructorID
  static let badServerSalt = TL.BadServerSalt.tlConstructorID
  static let newSessionCreated = TL.NewSessionCreated.tlConstructorID
  static let futureSalts = TL.FutureSalts.tlConstructorID
  static let msgsAck = TL.MsgsAck.tlConstructorID
  static let msgsStateInfo = TL.MsgsStateInfo.tlConstructorID
  static let msgDetailedInfo = TL.MsgDetailedInfo.tlConstructorID
  static let msgNewDetailedInfo = TL.MsgNewDetailedInfo.tlConstructorID

  // `msg_container messages:vector<%Message> = MessageContainer`
  static let msgContainer: UInt32 = 0x73f1_f8dc
  // `gzip_packed packed_data:bytes = Object`
  static let gzipPacked: UInt32 = 0x3072_cfa1
}
