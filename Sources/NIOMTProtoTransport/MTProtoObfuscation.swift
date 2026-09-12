import Crypto

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Builds the MTProto transport-obfuscation ("obfuscated2") handshake.
///
/// Obfuscation hides the recognizable transport magic and turns the whole
/// connection into a high-entropy AES-256-CTR stream, as described under
/// *Transport Obfuscation* in
/// <https://core.telegram.org/mtproto/mtproto-transports>. The 64-byte init
/// payload is laid out as:
///
/// ```
/// offset  0 ┌──────────────┐  random, unrecognizable preamble
///           │   8 bytes    │  (constrained — see makeRandomPayload)
/// offset  8 ├──────────────┤
///           │  32 bytes    │  AES key   (enc: this payload / dec: reversed)
/// offset 40 ├──────────────┤
///           │  16 bytes    │  AES IV    (enc: this payload / dec: reversed)
/// offset 56 ├──────────────┤
///           │   4 bytes    │  transport protocol tag (e.g. 0xefefefef)
/// offset 60 ├──────────────┤
///           │   2 bytes    │  DC id (MTProxy only), signed little-endian
/// offset 62 │   2 bytes    │  random
/// offset 64 └──────────────┘
/// ```
///
/// The payload is then encrypted with the *encryption* key/IV; the wire header
/// is the first 56 plaintext bytes followed by bytes 56–64 of the ciphertext.
public enum MTProtoObfuscation {
  /// First-4-byte little-endian words that must never begin the init payload:
  /// they would alias the recognizable transport magic (`0xeeeeeeee`,
  /// `0xdddddddd`) or HTTP request lines (`GET`, `POST`, `HEAD`, `OPTI…`).
  static let forbiddenLeadingWords: Set<UInt32> = [
    0x4441_4548,  // "HEAD"
    0x5453_4f50,  // "POST"
    0x2054_4547,  // "GET "
    0x4954_504f,  // "OPTI"
    0xeeee_eeee,  // intermediate magic
    0xdddd_dddd,  // padded-intermediate magic
  ]

  /// The product of a successful handshake: the bytes to send first, plus the
  /// two keystreams that encrypt/decrypt everything thereafter.
  public struct Handshake {
    /// The 64-byte header to send immediately after the TCP connection opens.
    public var header: [UInt8]
    /// The keystream for outbound bytes. Its counter has already advanced past
    /// the four blocks of the init payload.
    public var encrypt: AESCTRStream
    /// The keystream for inbound bytes.
    public var decrypt: AESCTRStream
  }

  /// Builds a handshake for `transport`, generating the random init payload
  /// with `rng`.
  ///
  /// - Parameters:
  ///   - transport: The framing to advertise. Must not be
  ///     ``MTProtoTransport/full`` (no protocol tag exists for it).
  ///   - secret: An optional MTProxy secret (16 bytes); when present the AES
  ///     keys become `SHA256(key ‖ secret)`.
  ///   - dcId: An optional data-center id written at offset 60 (MTProxy).
  public static func makeHandshake(
    transport: MTProtoTransport,
    secret: Data? = nil,
    dcId: Int16? = nil,
    using rng: inout some RandomNumberGenerator
  ) throws -> Handshake {
    let payload = makeRandomPayload(using: &rng)
    return try makeHandshake(
      transport: transport, secret: secret, dcId: dcId, initPayload: payload)
  }

  /// Generates 64 random bytes satisfying the leading-bytes constraints that
  /// keep the preamble from being mistaken for another transport or HTTP.
  static func makeRandomPayload(using rng: inout some RandomNumberGenerator) -> [UInt8] {
    var payload = [UInt8](repeating: 0, count: 64)
    repeat {
      for i in 0..<64 { payload[i] = rng.next() }
    } while !isValidPreamble(payload)
    return payload
  }

  /// Checks the first 8 bytes against the obfuscation preamble constraints.
  static func isValidPreamble(_ payload: [UInt8]) -> Bool {
    if payload[0] == 0xef { return false }
    let firstWord =
      UInt32(payload[0]) | UInt32(payload[1]) << 8
      | UInt32(payload[2]) << 16 | UInt32(payload[3]) << 24
    if forbiddenLeadingWords.contains(firstWord) { return false }
    let secondWord =
      UInt32(payload[4]) | UInt32(payload[5]) << 8
      | UInt32(payload[6]) << 16 | UInt32(payload[7]) << 24
    if secondWord == 0 { return false }  // would signal the full transport
    return true
  }

  /// Deterministic core: derives the handshake from an explicit 64-byte init
  /// payload. Exposed (internally) so tests can pin the random bytes.
  static func makeHandshake(
    transport: MTProtoTransport,
    secret: Data?,
    dcId: Int16?,
    initPayload: [UInt8]
  ) throws -> Handshake {
    guard let tag = transport.obfuscationTag else {
      throw MTProtoTransportError.obfuscationUnsupported(transport)
    }
    precondition(initPayload.count == 64, "obfuscation init payload must be 64 bytes")

    var payload = initPayload

    // Encryption key/IV from the payload; decryption key/IV from its reverse.
    var encKey = Data(payload[8..<40])
    let encIV = Data(payload[40..<56])
    let reversed = Array(payload.reversed())
    var decKey = Data(reversed[8..<40])
    let decIV = Data(reversed[40..<56])

    if let secret, !secret.isEmpty {
      encKey = Data(SHA256.hash(data: encKey + secret))
      decKey = Data(SHA256.hash(data: decKey + secret))
    }

    // Stamp the protocol tag at offset 56 and the optional DC id at offset 60.
    payload[56] = UInt8(truncatingIfNeeded: tag)
    payload[57] = UInt8(truncatingIfNeeded: tag >> 8)
    payload[58] = UInt8(truncatingIfNeeded: tag >> 16)
    payload[59] = UInt8(truncatingIfNeeded: tag >> 24)
    if let dcId {
      let bits = UInt16(bitPattern: dcId)
      payload[60] = UInt8(truncatingIfNeeded: bits)
      payload[61] = UInt8(truncatingIfNeeded: bits >> 8)
    }

    // Encrypt the whole payload; the encryption keystream then continues for
    // every subsequent outbound byte (its counter is now at block 4).
    var encrypt = AESCTRStream(key: encKey, iv: encIV)
    let encrypted = encrypt.apply(payload)
    let decrypt = AESCTRStream(key: decKey, iv: decIV)

    // Wire header: 56 plaintext bytes ‖ ciphertext[56..64].
    var header = Array(payload[0..<56])
    header.append(contentsOf: encrypted[56..<64])

    return Handshake(header: header, encrypt: encrypt, decrypt: decrypt)
  }

  /// The result of accepting the peer's obfuscation handshake: the transport it
  /// asked for plus the two keystreams (already advanced past the 64-byte
  /// init).
  public struct AcceptedHandshake {
    /// The transport the initiator requested (decoded from the tag at offset
    /// 56).
    public var transport: MTProtoTransport
    /// Keystream for inbound bytes — the initiator's encryption stream.
    public var decrypt: AESCTRStream
    /// Keystream for outbound bytes — the initiator's decryption stream.
    public var encrypt: AESCTRStream
  }

  /// Accepts an obfuscation handshake from the 64 init bytes the initiator sent
  /// — the other end of ``makeHandshake(transport:secret:dcId:using:)``, as
  /// needed by anything that terminates an obfuscated connection (an MTProxy,
  /// a relay, a test double).
  ///
  /// The initiator derived its *encryption* key/IV from bytes `8..56` of the
  /// payload and its *decryption* key/IV from the reversed payload; the
  /// accepting end mirrors this — its decryption stream equals the initiator's
  /// encryption stream and vice versa. The 64 received bytes are run through the
  /// decryption stream both to advance its counter past the header and to
  /// recover the transport tag stamped (encrypted) at offset 56.
  ///
  /// - Parameter received: exactly 64 bytes — the initiator's obfuscation
  ///   header.
  /// - Parameter secret: an optional MTProxy secret folded into the keys.
  public static func acceptHandshake(
    received: [UInt8], secret: Data? = nil
  ) throws -> AcceptedHandshake {
    guard received.count == 64 else {
      throw MTProtoTransportError.invalidObfuscationHeaderLength(received.count)
    }

    // The initiator's encryption key/IV (= our decryption key/IV).
    var decKey = Data(received[8..<40])
    let decIV = Data(received[40..<56])
    // The initiator's decryption key/IV (= our encryption key/IV), from the
    // reversed payload.
    let reversed = Array(received.reversed())
    var encKey = Data(reversed[8..<40])
    let encIV = Data(reversed[40..<56])

    if let secret, !secret.isEmpty {
      decKey = Data(SHA256.hash(data: decKey + secret))
      encKey = Data(SHA256.hash(data: encKey + secret))
    }

    var decrypt = AESCTRStream(key: decKey, iv: decIV)
    let encrypt = AESCTRStream(key: encKey, iv: encIV)

    // Decrypt the whole 64-byte header: this advances the inbound counter to
    // block 4 and yields the transport tag at bytes 56..60.
    let plaintext = decrypt.apply(received)
    let tag =
      UInt32(plaintext[56]) | UInt32(plaintext[57]) << 8
      | UInt32(plaintext[58]) << 16 | UInt32(plaintext[59]) << 24

    guard let transport = MTProtoTransport.allCases.first(where: { $0.obfuscationTag == tag })
    else {
      throw MTProtoTransportError.unrecognizedTransport(tag: tag)
    }

    return AcceptedHandshake(transport: transport, decrypt: decrypt, encrypt: encrypt)
  }
}
