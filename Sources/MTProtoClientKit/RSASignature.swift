import Crypto
import MTProtoCrypto

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

// RSASSA-PKCS1-v1.5 sign/verify over SHA-256, layered on the raw modular
// exponentiation the handshake crypto already provides (`RSAPrivateKey.rawDecrypt`
// = `m^d mod n`, `RSAPublicKey.rawEncrypt` = `m^e mod n`). The private-key
// complement of the handshake's public-key encryption, for peer-authentication
// schemes layered above MTProto that need to prove possession of an RSA key.
//
// PKCS#1 v1.5 is chosen over PSS for determinism and simplicity; it is adequate
// here because the signed message is a fixed-layout, domain-separated tuple, not
// attacker-chosen ciphertext.

/// The DER `DigestInfo` prefix for a SHA-256 digest (RFC 8017 §9.2). The full
/// `T` is this ‖ the 32-byte hash (51 bytes total).
private let sha256DigestInfoPrefix: [UInt8] = [
  0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
  0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
]

/// Builds the `emLen`-byte EMSA-PKCS1-v1.5 encoding of `message`'s SHA-256:
/// `0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ DigestInfo ‖ H` where `PS` is `0xFF` padding.
/// Returns `nil` if `emLen` is too small to hold the block (never for a
/// ≥ 2048-bit modulus).
private func emsaPKCS1v15SHA256(_ message: Data, emLen: Int) -> Data? {
  let hash = Array(SHA256.hash(data: message))
  let t = sha256DigestInfoPrefix + hash  // 51 bytes
  // At least 8 bytes of 0xFF padding are required (RFC 8017 §9.2 step 3).
  guard emLen >= t.count + 11 else { return nil }
  var em = Data([0x00, 0x01])
  em.append(contentsOf: [UInt8](repeating: 0xFF, count: emLen - t.count - 3))
  em.append(0x00)
  em.append(contentsOf: t)
  return em
}

extension RSAPrivateKey {
  /// RSASSA-PKCS1-v1.5 signature over `SHA256(message)`, returning the
  /// `modulusByteCount`-byte big-endian signature. Traps only if the modulus is
  /// too small to hold the encoded block (a misconfigured, non-2048-bit key).
  public func signSHA256(_ message: Data) -> Data {
    guard let em = emsaPKCS1v15SHA256(message, emLen: modulusByteCount) else {
      preconditionFailure("RSA modulus too small for a PKCS#1 v1.5 SHA-256 signature")
    }
    // s = EM^d mod n — the raw private-key operation.
    return rawDecrypt(em)
  }
}

extension RSAPublicKey {
  /// Verifies an RSASSA-PKCS1-v1.5 `signature` over `SHA256(message)`. Recovers
  /// `EM = signature^e mod n` and constant-time-compares it to the expected
  /// encoding. Rejects malformed inputs (wrong length, bad modulus) rather than
  /// trapping.
  public func verifySHA256(_ signature: Data, message: Data) -> Bool {
    guard signature.count == modulusByteCount,
      let expected = emsaPKCS1v15SHA256(message, emLen: modulusByteCount)
    else { return false }
    let recovered = rawEncrypt(signature)  // s^e mod n, left-padded to modulusByteCount
    return constantTimeEquals(recovered, expected)
  }
}

/// Length-independent-of-content byte comparison. Lengths are equal by
/// construction here (both `modulusByteCount`); the loop avoids a data-dependent
/// early exit anyway.
private func constantTimeEquals(_ a: Data, _ b: Data) -> Bool {
  guard a.count == b.count else { return false }
  var diff: UInt8 = 0
  for (x, y) in zip(a, b) { diff |= x ^ y }
  return diff == 0
}
