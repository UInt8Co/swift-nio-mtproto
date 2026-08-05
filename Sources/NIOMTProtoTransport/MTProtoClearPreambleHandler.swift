import NIOCore

/// Sends the clear-text transport preamble (the magic bytes `0xef`,
/// `0xeeeeeeee` or `0xdddddddd`) once, when the connection becomes active.
///
/// Used only when the transport is *not* obfuscated; with obfuscation the
/// protocol is identified inside the ``MTProtoObfuscation`` header instead, so
/// ``MTProtoObfuscationHandler`` takes this handler's place at the head of the
/// pipeline. ``MTProtoTransport/full`` has no preamble, so this handler then
/// only forwards events.
public final class MTProtoClearPreambleHandler: ChannelInboundHandler {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer

  private let transport: MTProtoTransport

  public init(transport: MTProtoTransport) {
    self.transport = transport
  }

  public func channelActive(context: ChannelHandlerContext) {
    let preamble = transport.clearPreamble
    if !preamble.isEmpty {
      var buffer = context.channel.allocator.buffer(capacity: preamble.count)
      buffer.writeBytes(preamble)
      context.writeAndFlush(NIOAny(buffer), promise: nil)
    }
    context.fireChannelActive()
  }
}
