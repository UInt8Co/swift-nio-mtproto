import MTProtoBaseSchema
import MTProtoClientKit
import TLCoding
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

@Suite struct ClientHandshakeSecurityTests {
  @Test(arguments: [0, 9, 256])
  func rejectsOversizedPQBeforeFactorizationOrRSA(_ length: Int) throws {
    let key = RSAPublicKey(testRSAKey)
    var handshake = MTProtoClientHandshake(rsaKey: key)
    var reader = TLReader(handshake.start())
    let nonce = try TL.ReqPqMulti(tlFrom: &reader).nonce
    // The low bytes form a valid small semiprime, so truncating to UInt64
    // would let the oversized original string reach RSA_PAD and trap.
    var pq = Data(repeating: 0, count: length)
    if length > 0 { pq[length - 1] = 15 }
    let reply = TL.ResPQ(
      nonce: nonce, serverNonce: .zero, pq: pq,
      serverPublicKeyFingerprints: [key.fingerprint]
    ).tlSerialized()
    #expect(throws: MTProtoClientHandshakeError.invalidPQ) {
      try handshake.process(messageBody: reply)
    }
  }
}
