import Crypto
import MTProtoCrypto
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// An RSA *public* key, used by an MTProto client to encrypt `p_q_inner_data`
/// to a server during the auth-key handshake — the counterpart of
/// `MTProtoCrypto.RSAPrivateKey` (a candidate to move upstream beside it).
///
/// MTProto does not use a standard RSA padding for the handshake; the client
/// raises a fixed-layout block to the public exponent modulo `n`
/// (``rawEncrypt(_:)``). ``encryptRSAPad(_:)`` builds the summer-2021 RSA_PAD
/// AES/SHA-256 construction — the layout official clients and GramJS /
/// telegram-tt use; the older one is `SHA1(data) ‖ data ‖ random`.
public struct RSAPublicKey: Sendable {
  /// Modulus `n`.
  public let modulus: BigUInt
  /// Public exponent `e` (usually 65537).
  public let publicExponent: BigUInt
  /// Size of the modulus in bytes (256 for a 2048-bit key).
  public let modulusByteCount: Int

  public init(modulus: BigUInt, publicExponent: BigUInt) {
    self.modulus = modulus
    self.publicExponent = publicExponent
    self.modulusByteCount = (modulus.bitWidth + 7) / 8
  }

  /// Builds a key from big-endian byte representations of `n` and `e`.
  public init(
    modulusBytes: some Collection<UInt8>,
    publicExponentBytes: some Collection<UInt8>
  ) {
    self.init(
      modulus: BigUInt(bigEndianBytes: modulusBytes),
      publicExponent: BigUInt(bigEndianBytes: publicExponentBytes))
  }

  /// Builds a key from hexadecimal big-endian representations of `n` and `e`.
  public init?(modulusHex: String, publicExponentHex: String) {
    guard let n = [UInt8](hex: modulusHex), let e = [UInt8](hex: publicExponentHex)
    else { return nil }
    self.init(modulusBytes: n, publicExponentBytes: e)
  }

  /// The public half of a private key.
  public init(_ privateKey: RSAPrivateKey) {
    self.init(modulus: privateKey.modulus, publicExponent: privateKey.publicExponent)
  }

  // MARK: - Fingerprint

  /// The MTProto public-key fingerprint: the low 64 bits of
  /// `SHA1(bytes(n) ‖ bytes(e))`, read little-endian, where `bytes(·)` is the
  /// TL `bytes` serialization of the minimal big-endian integer. Matches
  /// `RSAPrivateKey.fingerprint` for the same key, and is the value a client
  /// looks up in `resPQ.server_public_key_fingerprints`.
  public var fingerprint: Int64 {
    var writer = TLWriter()
    writer.writeBytes(modulus.bigEndianBytes())
    writer.writeBytes(publicExponent.bigEndianBytes())
    let digest = Array(Insecure.SHA1.hash(data: writer.data))  // 20 bytes
    var value: UInt64 = 0
    for (i, byte) in digest[12..<20].enumerated() {
      value |= UInt64(byte) << (8 * i)
    }
    return Int64(bitPattern: value)
  }

  // MARK: - Raw RSA

  /// Raw RSA public-key operation: `plaintext^e mod n`, returning the
  /// `modulusByteCount`-byte big-endian result.
  public func rawEncrypt(_ plaintext: Data) -> Data {
    let m = BigUInt(bigEndianBytes: plaintext)
    return m.power(publicExponent, modulus: modulus)
      .bigEndianBytes(byteCount: modulusByteCount)
  }

  /// Encrypts `data` (≤ 144 bytes; a serialized `p_q_inner_data`) with the
  /// summer-2021 **RSA_PAD** construction — the exact inverse of
  /// `RSAPrivateKey.recoverDataFromRSAPad(_:)`:
  ///
  /// ```
  /// data_with_padding = data ‖ random           (to 192 bytes)
  /// data_pad_reversed = reverse(data_with_padding)
  /// temp_key          = random(32)               (retried until the block < n)
  /// data_with_hash    = data_pad_reversed ‖ SHA256(temp_key ‖ data_with_padding)
  /// aes_encrypted     = AES256_IGE_encrypt(data_with_hash, key: temp_key, iv: 0)
  /// key_aes_encrypted = (temp_key XOR SHA256(aes_encrypted)) ‖ aes_encrypted
  /// encrypted_data    = key_aes_encrypted^e mod n
  /// ```
  public func encryptRSAPad(_ data: Data) -> Data {
    precondition(data.count <= 144, "RSA_PAD payload must be at most 144 bytes")
    let dataWithPadding = data + randomData(192 - data.count)
    let dataPadReversed = Data(dataWithPadding.reversed())
    while true {
      let tempKey = randomData(32)
      let dataWithHash =
        dataPadReversed + Data(SHA256.hash(data: tempKey + dataWithPadding))
      // 224 bytes, a multiple of 16, with a just-generated random key: IGE
      // cannot fail here.
      let aesEncrypted = try! AESIGE.encrypt(
        dataWithHash, key: tempKey, iv: Data(repeating: 0, count: 32))
      var tempKeyXor = [UInt8](tempKey)
      let aesHash = Array(SHA256.hash(data: aesEncrypted))
      for i in 0..<32 { tempKeyXor[i] ^= aesHash[i] }
      let block = Data(tempKeyXor) + aesEncrypted
      // The 256-byte block must be numerically below the modulus; retry with
      // a fresh temp key otherwise, exactly as reference clients do.
      guard BigUInt(bigEndianBytes: block) < modulus else { continue }
      return rawEncrypt(block)
    }
  }
}

/// Cryptographically random bytes (module-local; mirrors
/// `NIOMTProtoEncryption.randomData` without depending on it here).
func randomData(_ count: Int) -> Data {
  var rng = SystemRandomNumberGenerator()
  var bytes = [UInt8](repeating: 0, count: count)
  for i in 0..<count { bytes[i] = rng.next() }
  return Data(bytes)
}

extension [UInt8] {
  /// Parses a hexadecimal string (no `0x`, even length) into bytes.
  init?(hex: String) {
    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var pendingHigh: Int? = nil
    for character in hex {
      guard let value = character.hexDigitValue else { return nil }
      if let high = pendingHigh {
        bytes.append(UInt8(high << 4 | value))
        pendingHigh = nil
      } else {
        pendingHigh = value
      }
    }
    guard pendingHigh == nil else { return nil }
    self = bytes
  }
}
