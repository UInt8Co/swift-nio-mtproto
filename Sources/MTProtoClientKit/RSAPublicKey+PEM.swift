import MTProtoCrypto

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

extension RSAPublicKey {
  /// Parses a PEM-encoded RSA public key into the raw `(n, e)` this type needs
  /// for the MTProto handshake. Accepts both PKCS#1 (`-----BEGIN RSA PUBLIC
  /// KEY-----`) and SPKI (`-----BEGIN PUBLIC KEY-----`) layouts, so a key
  /// pasted from Telegram's docs or emitted by `openssl` both work.
  ///
  /// Just enough DER is walked to reach the two `INTEGER`s; a malformed or
  /// non-RSA key returns `nil`.
  public init?(pem: String) {
    guard let der = RSAPublicKey.derBody(fromPEM: pem) else { return nil }
    guard let (n, e) = RSAPublicKey.parsePublicKeyDER(der) else { return nil }
    self.init(modulusBytes: n, publicExponentBytes: e)
  }

  /// Strips the `-----BEGIN …-----` / `-----END …-----` armor and base64-decodes
  /// the body.
  private static func derBody(fromPEM pem: String) -> [UInt8]? {
    let base64 =
      pem
      .split(whereSeparator: \.isNewline)
      .filter { !$0.hasPrefix("-----") }
      .joined()
    guard let data = Data(base64Encoded: base64) else { return nil }
    return [UInt8](data)
  }

  /// Returns `(modulus, publicExponent)` as minimal big-endian magnitudes from
  /// either a PKCS#1 `RSAPublicKey` or an SPKI `SubjectPublicKeyInfo` DER.
  private static func parsePublicKeyDER(_ der: [UInt8]) -> (n: [UInt8], e: [UInt8])? {
    var outer = DERScanner(der)
    guard var seq = try? outer.readSequence() else { return nil }
    // Peek the first element's tag: INTEGER → PKCS#1; SEQUENCE → SPKI.
    guard let firstTag = seq.peekTag() else { return nil }
    if firstTag == 0x02 {
      // PKCS#1: SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
      guard let n = try? seq.readInteger(), let e = try? seq.readInteger() else { return nil }
      return (n, e)
    }
    if firstTag == 0x30 {
      // SPKI: SEQUENCE { algorithm SEQUENCE, subjectPublicKey BIT STRING }.
      _ = try? seq.skip()  // AlgorithmIdentifier
      guard let bitString = try? seq.readBitString() else { return nil }
      var inner = DERScanner(bitString)
      guard var innerSeq = try? inner.readSequence(),
        let n = try? innerSeq.readInteger(), let e = try? innerSeq.readInteger()
      else { return nil }
      return (n, e)
    }
    return nil
  }
}

/// A tiny DER reader — walks SEQUENCE / INTEGER / BIT STRING only, enough to
/// reach an RSA public key's `(n, e)`.
private struct DERScanner {
  private let bytes: [UInt8]
  private var pos: Int

  init(_ bytes: [UInt8]) {
    self.bytes = bytes
    self.pos = 0
  }
  init(_ slice: ArraySlice<UInt8>) {
    self.bytes = Array(slice)
    self.pos = 0
  }

  enum DERError: Error { case truncated, malformed, unexpectedTag }

  func peekTag() -> UInt8? { pos < bytes.count ? bytes[pos] : nil }

  private mutating func readByte() throws -> UInt8 {
    guard pos < bytes.count else { throw DERError.truncated }
    defer { pos += 1 }
    return bytes[pos]
  }

  private mutating func readLength() throws -> Int {
    let first = try readByte()
    if first & 0x80 == 0 { return Int(first) }
    let count = Int(first & 0x7F)
    guard count > 0, count <= 8 else { throw DERError.malformed }
    var length = 0
    for _ in 0..<count { length = (length << 8) | Int(try readByte()) }
    return length
  }

  private mutating func readValue(tag: UInt8) throws -> ArraySlice<UInt8> {
    let actual = try readByte()
    guard actual == tag else { throw DERError.unexpectedTag }
    let length = try readLength()
    guard pos + length <= bytes.count else { throw DERError.truncated }
    defer { pos += length }
    return bytes[pos..<pos + length]
  }

  /// Reads a SEQUENCE (0x30) and returns a scanner over its contents.
  mutating func readSequence() throws -> DERScanner { DERScanner(try readValue(tag: 0x30)) }

  /// Reads an INTEGER (0x02) as a minimal big-endian magnitude (sign byte
  /// stripped).
  mutating func readInteger() throws -> [UInt8] {
    let raw = Array(try readValue(tag: 0x02))
    let trimmed = Array(raw.drop { $0 == 0 })
    return trimmed.isEmpty ? [0] : trimmed
  }

  /// Reads a BIT STRING (0x03) and returns its payload minus the leading
  /// unused-bits count byte.
  mutating func readBitString() throws -> ArraySlice<UInt8> {
    var value = try readValue(tag: 0x03)
    guard let first = value.first, first == 0 else { throw DERError.malformed }
    value = value.dropFirst()
    return value
  }

  /// Skips one TLV element of any tag.
  mutating func skip() throws {
    _ = try readByte()
    let length = try readLength()
    guard pos + length <= bytes.count else { throw DERError.truncated }
    pos += length
  }
}
