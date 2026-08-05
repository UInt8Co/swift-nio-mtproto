import MTProtoCrypto

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The repo's test RSA key (`Fixtures/test-rsa-key.json`). A *private* key: the
/// tests need to decrypt what the client encrypts to a peer's public half.
let testRSAKey: RSAPrivateKey = {
  struct KeyJSON: Decodable {
    let n: String
    let e: String
    let d: String
  }
  let url = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // MTProtoClientKitTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // repo root
    .appendingPathComponent("Fixtures/test-rsa-key.json")
  guard let data = try? Data(contentsOf: url),
    let key = try? JSONDecoder().decode(KeyJSON.self, from: data),
    let rsa = RSAPrivateKey(
      modulusHex: key.n, publicExponentHex: key.e, privateExponentHex: key.d)
  else {
    fatalError("failed to load the test RSA key from \(url.path)")
  }
  return rsa
}()
