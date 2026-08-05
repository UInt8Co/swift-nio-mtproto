import Crypto
import MTProtoClientKit
import MTProtoCrypto
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The client-side crypto primitives: the RSA public-key operations (the one
/// genuinely new client-side crypto op) and `pq` factorization.
@Suite struct RSAPublicKeyTests {
  @Test func fingerprintMatchesThePrivateKey() {
    #expect(RSAPublicKey(testRSAKey).fingerprint == testRSAKey.fingerprint)
  }

  @Test func rawEncryptInvertsRawDecrypt() {
    let publicKey = RSAPublicKey(testRSAKey)
    // A random block below the modulus (top byte zeroed keeps it below).
    var block = [UInt8](repeating: 0, count: publicKey.modulusByteCount)
    var rng = SystemRandomNumberGenerator()
    for i in 1..<block.count { block[i] = rng.next() }
    let plaintext = Data(block)
    #expect(testRSAKey.rawDecrypt(publicKey.rawEncrypt(plaintext)) == plaintext)
  }

  @Test func rsaPadEncryptionIsRecoverableWithThePrivateKey() throws {
    let publicKey = RSAPublicKey(testRSAKey)
    let payload = Data((0..<100).map { UInt8($0) })
    let encrypted = publicKey.encryptRSAPad(payload)
    let recovered = try #require(testRSAKey.recoverDataFromRSAPad(encrypted))
    // recoverDataFromRSAPad returns data ‖ random padding (192 bytes total);
    // the payload sits at the front.
    #expect(recovered.count == 192)
    #expect(recovered.prefix(payload.count) == payload)
  }

  @Test func rsaPadTamperingIsRejectedOnRecovery() {
    let publicKey = RSAPublicKey(testRSAKey)
    var encrypted = publicKey.encryptRSAPad(Data([1, 2, 3]))
    encrypted[encrypted.startIndex] ^= 0xFF
    #expect(testRSAKey.recoverDataFromRSAPad(encrypted) == nil)
  }
}

@Suite struct PQFactorizationTests {
  @Test func factorsGeneratedChallenges() throws {
    for _ in 0..<8 {
      let challenge = PQChallenge.random()
      let factors = try #require(PQFactorization.factor(challenge.pq))
      #expect(factors.p == challenge.p)
      #expect(factors.q == challenge.q)
    }
  }

  @Test func factorsAKnownSemiprime() throws {
    let factors = try #require(PQFactorization.factor(0x17ED_4894_1A08_F981))
    #expect(UInt64(factors.p) * UInt64(factors.q) == 0x17ED_4894_1A08_F981)
    #expect(factors.p < factors.q)
  }

  @Test func handlesSmallFactors() throws {
    let factors = try #require(PQFactorization.factor(2 * 2_147_483_647))
    #expect(factors.p == 2)
    #expect(factors.q == 2_147_483_647)
  }

  @Test func rejectsNonSemiprimes() {
    // A prime: rho can never split it.
    #expect(PQFactorization.factor(2_147_483_647) == nil)
    #expect(PQFactorization.factor(1) == nil)
  }
}
