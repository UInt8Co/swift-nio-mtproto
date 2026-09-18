import MTProtoClientKit
import MTProtoCrypto
import NIOMTProtoEncryption
import Testing

@Suite struct SessionBindingTests {
  @Test func bindingIsLiveAndNewOnResume() async throws {
    let key = randomData(256)
    let configuration = MTProtoClientConfiguration(
      rsaPublicKey: RSAPublicKey(testRSAKey), resumeSession: .init(authKey: key, serverSalt: 0),
      pingInterval: nil)
    let first = MTProtoClientConnection(configuration: configuration)
    #expect(await first.sessionBinding() == nil)
    await first.channelActive(write: { _ in }, close: {})
    let binding = try #require(await first.sessionBinding())
    #expect(binding.authKeyID == MTProtoMessageCrypto.authKeyID(key))
    #expect(binding.sessionID != 0)
    #expect(await first.sessionBinding() == binding)
    await first.channelInactive()
    #expect(await first.sessionBinding() == nil)
    let second = MTProtoClientConnection(configuration: configuration)
    await second.channelActive(write: { _ in }, close: {})
    let resumed = try #require(await second.sessionBinding())
    #expect(resumed.authKeyID == binding.authKeyID)
    #expect(resumed.sessionID != binding.sessionID)
    await second.channelInactive()
  }
}
