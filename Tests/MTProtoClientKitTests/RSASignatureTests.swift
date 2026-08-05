import MTProtoCrypto
import Testing

@testable import MTProtoClientKit

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// RSASSA-PKCS1-v1.5 (SHA-256) sign/verify over the handshake's raw RSA.
@Suite struct RSASignatureTests {
  private let publicKey = RSAPublicKey(testRSAKey)

  @Test func signThenVerifyRoundTrips() {
    let message = Data("the quick brown fox".utf8)
    let signature = testRSAKey.signSHA256(message)
    #expect(signature.count == testRSAKey.modulusByteCount)
    #expect(publicKey.verifySHA256(signature, message: message))
  }

  @Test func verifyRejectsWrongMessage() {
    let signature = testRSAKey.signSHA256(Data("original".utf8))
    #expect(!publicKey.verifySHA256(signature, message: Data("tampered".utf8)))
  }

  @Test func verifyRejectsTamperedSignature() {
    let message = Data("payload".utf8)
    var signature = testRSAKey.signSHA256(message)
    signature[signature.count / 2] ^= 0x01
    #expect(!publicKey.verifySHA256(signature, message: message))
  }

  @Test func verifyRejectsWrongLengthSignature() {
    let message = Data("payload".utf8)
    let signature = testRSAKey.signSHA256(message)
    #expect(!publicKey.verifySHA256(signature.dropLast(), message: message))
  }

  @Test func verifyRejectsWrongKey() {
    let message = Data("payload".utf8)
    let signature = testRSAKey.signSHA256(message)
    // A different modulus of the same byte length: not the signer's key.
    var modBytes = [UInt8](publicKey.modulus.bigEndianBytes())
    modBytes[0] ^= 0x80
    let otherKey = RSAPublicKey(
      modulusBytes: modBytes,
      publicExponentBytes: publicKey.publicExponent.bigEndianBytes())
    #expect(!otherKey.verifySHA256(signature, message: message))
  }

  @Test func emptyMessageSigns() {
    let signature = testRSAKey.signSHA256(Data())
    #expect(publicKey.verifySHA256(signature, message: Data()))
  }
}
