import MTProtoCrypto

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The Diffie–Hellman group an MTProto server offers during the auth-key
/// handshake (`g` and `dh_prime` in `server_DH_inner_data`).
public struct MTProtoDHParameters: Sendable {
  /// The generator `g`.
  public let g: Int32
  /// The safe prime `p`, big-endian.
  public let primeBytes: Data

  public init(g: Int32, primeBytes: Data) {
    self.g = g
    self.primeBytes = primeBytes
  }

  /// The well-known 2048-bit safe prime production Telegram servers use —
  /// clients (including mtcute) ship it as a trusted constant and skip the
  /// expensive Miller–Rabin validation when they see it — together with the
  /// generator `g = 3` (which satisfies the client's `dh_prime mod 3 == 2`
  /// check for `g = 3`).
  public static let telegram2048 = MTProtoDHParameters(
    g: 3,
    primeBytes: Data(
      [UInt8](
        hex: "C71CAEB9C6B1C9048E6C522F70F13F73980D40238E3E21C14934D037563D930F"
          + "48198A0AA7C14058229493D22530F4DBFA336F6E0AC925139543AED44CCE7C37"
          + "20FD51F69458705AC68CD4FE6B6B13ABDC9746512969328454F18FAF8C595F64"
          + "2477FE96BB2A941D5BCD1D4AC8CC49880708FA9B378E3C4F3A9060BEE67CF9A4"
          + "A4A695811051907E162753B56B0F6B410DBA74D8A84B2A14B3144E0EF1284754"
          + "FD17ED950D5965B4B9DD46582DB1178D169C6BC465B0D6FF9CA3928FEF5B9AE4"
          + "E418FC15E83EBEA0F87FA9FF5EED70050DED2849F47BF959D956850CE929851F"
          + "0D8115F635B105EE2E4E15D04B2454BF6F4FADF034B10403119CD8E3B92FCC5B")!))

  /// The prime as a big integer.
  public var prime: BigUInt { BigUInt(bigEndianBytes: primeBytes) }
  /// The generator as a big integer.
  public var generator: BigUInt { BigUInt(UInt32(bitPattern: g)) }
  /// The size of the prime in bytes (256 for a 2048-bit group).
  public var byteCount: Int { primeBytes.count }

  /// Picks a random secret exponent the size of the prime.
  public func randomExponent() -> BigUInt {
    var bytes = [UInt8](repeating: 0, count: byteCount)
    var rng = SystemRandomNumberGenerator()
    for i in 0..<bytes.count { bytes[i] = rng.next() }
    return BigUInt(bigEndianBytes: bytes)
  }

  /// `g^secret mod p` — a public DH value (`g_a` / `g_b`).
  public func publicValue(secret: BigUInt) -> BigUInt {
    generator.power(secret, modulus: prime)
  }

  /// `peerPublic^secret mod p`, padded to the group size — the shared key.
  public func sharedSecret(peerPublic: BigUInt, secret: BigUInt) -> Data {
    peerPublic.power(secret, modulus: prime).bigEndianBytes(byteCount: byteCount)
  }

  /// The lower safety bound for DH public values: `2^{8·(byteCount−8)}`
  /// (i.e. `2^{2048−64}` for the 2048-bit group), built as a `1` byte followed
  /// by `byteCount − 8` zero bytes.
  public var safeLowerBound: BigUInt {
    BigUInt(bigEndianBytes: [0x01] + [UInt8](repeating: 0, count: byteCount - 8))
  }

  /// Whether `value` lies in the safe DH range
  /// `2^{2048-64} < value < p − 2^{2048-64}`, per Telegram's security
  /// guidelines (<https://core.telegram.org/mtproto/security_guidelines>).
  /// Both `g_a` (server-chosen) and `g_b` (client-supplied) must satisfy it.
  public func isSafePublicValue(_ value: BigUInt) -> Bool {
    let lower = safeLowerBound
    return value > lower && value < prime - lower
  }
}

extension [UInt8] {
  /// Local hex parser mirroring `MTProtoCrypto`'s (kept module-private).
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
