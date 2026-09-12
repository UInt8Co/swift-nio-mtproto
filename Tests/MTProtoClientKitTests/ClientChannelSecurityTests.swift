import MTProtoCrypto
import NIOCore
import NIOEmbedded
import NIOMTProtoEncryption
import Testing

@testable import MTProtoClientKit

@Suite struct ClientChannelSecurityTests {
  @Test(arguments: [true, false])
  func closesWhenInboundProcessingBacklogExceedsLimit(bytesLimit: Bool) async throws {
    let connection = MTProtoClientConnection(
      configuration: .init(
        rsaPublicKey: RSAPublicKey(testRSAKey),
        resumeSession: .init(authKey: NIOMTProtoEncryption.randomData(256), serverSalt: 0),
        pingInterval: nil))
    let channel = try await NIOAsyncTestingChannel { channel in
      try channel.pipeline.syncOperations.addHandler(
        MTProtoClientChannelHandler(
          connection: connection,
          maximumPendingBytes: bytesLimit ? 16 : Int.max,
          maximumPendingMessages: bytesLimit ? 1024 : 2))
    }
    try await channel.connect(to: SocketAddress(ipAddress: "127.0.0.1", port: 1))
    let stayedWithinLimit = try await channel.eventLoop.submit {
      var payload = channel.allocator.buffer(capacity: 8)
      payload.writeInteger(Int64(1))
      // One event-loop turn: actor completions cannot release capacity in
      // the middle of this incoming batch.
      channel.pipeline.fireChannelRead(NIOAny(payload))
      channel.pipeline.fireChannelRead(NIOAny(payload))
      let activeBeforeLimit = channel.isActive
      channel.pipeline.fireChannelRead(NIOAny(payload))
      return activeBeforeLimit && !channel.isActive
    }.get()
    #expect(stayedWithinLimit)
    _ = try await channel.finish(acceptAlreadyClosed: true)
    await connection.channelInactive()
  }
}
