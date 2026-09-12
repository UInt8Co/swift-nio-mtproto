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
  private let maximumPendingBytes: Int
  private let maximumPendingMessages: Int
  private var pendingBytes = 0
  private var pendingMessages = 0
  private var closing = false

  init(
    connection: MTProtoClientConnection,
    maximumPendingBytes: Int = 32 << 20,
    maximumPendingMessages: Int = 1024
  ) {
    self.connection = connection
    self.maximumPendingBytes = maximumPendingBytes
    self.maximumPendingMessages = maximumPendingMessages
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
    guard !closing else { return }
    let buffer = unwrapInboundIn(data)
    // Framing limits each packet, but the actor may process packets more
    // slowly than the network receives them. Bound retained bytes and Tasks
    // before copying the next payload into the serial processing chain.
    guard buffer.readableBytes <= maximumPendingBytes - pendingBytes,
      pendingMessages < maximumPendingMessages
    else {
      closing = true
      context.close(promise: nil)
      return
    }
    let payload = Data(buffer.readableBytesView)
    pendingBytes += payload.count
    pendingMessages += 1
    let connection = self.connection
    let previous = tail
    let handler = NIOLoopBound(self, eventLoop: context.eventLoop)
    let eventLoop = context.eventLoop
    tail = Task {
      await previous?.value
      await connection.handleInbound(payload)
      eventLoop.execute {
        handler.value.pendingBytes -= payload.count
        handler.value.pendingMessages -= 1
      }
    }
  }

  func channelInactive(context: ChannelHandlerContext) {
    closing = true
    let connection = self.connection
    let previous = tail
    tail = Task {
      await previous?.value
      await connection.channelInactive()
    }
    context.fireChannelInactive()
  }

  func errorCaught(context: ChannelHandlerContext, error: Error) {
    closing = true
    context.close(promise: nil)
  }
}
