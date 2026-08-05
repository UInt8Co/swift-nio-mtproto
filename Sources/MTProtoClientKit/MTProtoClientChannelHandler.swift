import NIOCore

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Bridges the raw MTProto payload stream (from the ``NIOMTProtoTransport``
/// handlers below it) to an ``MTProtoClientConnection`` actor.
///
/// On `channelActive` it hands the connection a thread-safe write/close pair
/// (so the actor can drive the handshake and send messages). Inbound payloads
/// are processed by the actor; because separate `Task`s could otherwise be
/// reordered, they are chained so payloads are handled in arrival order.
final class MTProtoClientChannelHandler: ChannelInboundHandler {
  typealias InboundIn = ByteBuffer
  typealias OutboundOut = ByteBuffer

  private let connection: MTProtoClientConnection
  /// Tail of the serial processing chain; each read awaits the previous.
  private var tail: Task<Void, Never>?

  init(connection: MTProtoClientConnection) {
    self.connection = connection
  }

  func channelActive(context: ChannelHandlerContext) {
    let connection = self.connection
    let channel = context.channel
    let write: @Sendable (Data) -> Void = { [weak channel] payload in
      guard let channel else { return }
      var buffer = channel.allocator.buffer(capacity: payload.count)
      buffer.writeBytes(payload)
      channel.writeAndFlush(buffer, promise: nil)
    }
    let close: @Sendable () -> Void = { [weak channel] in
      channel?.close(promise: nil)
    }
    tail = Task { await connection.channelActive(write: write, close: close) }
    context.fireChannelActive()
  }

  func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let payload = Data(unwrapInboundIn(data).readableBytesView)
    let connection = self.connection
    let previous = tail
    tail = Task {
      await previous?.value
      await connection.handleInbound(payload)
    }
  }

  func channelInactive(context: ChannelHandlerContext) {
    let connection = self.connection
    let previous = tail
    tail = Task {
      await previous?.value
      await connection.channelInactive()
    }
    context.fireChannelInactive()
  }
}
