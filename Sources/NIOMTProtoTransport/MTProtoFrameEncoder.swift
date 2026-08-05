import MTProtoUtils
import NIOCore

/// Wraps outbound MTProto payloads in the envelope of the configured
/// ``MTProtoTransport`` before they are written to the socket (or to the
/// obfuscation layer, when present).
///
/// Implemented as a `ChannelOutboundHandler` rather than a
/// `MessageToByteEncoder` because the ``MTProtoTransport/full`` transport
/// carries a per-connection sequence number that must be mutated on every
/// write.
///
/// Each `write` expects a single `ByteBuffer` payload. For every transport
/// except ``MTProtoTransport/paddedIntermediate`` the payload must be a
/// multiple of four bytes long (every MTProto message already is); this is
/// asserted as a precondition.
public final class MTProtoFrameEncoder: ChannelOutboundHandler {
  public typealias OutboundIn = ByteBuffer
  public typealias OutboundOut = ByteBuffer

  /// The transport whose framing is being produced.
  public let transport: MTProtoTransport

  /// The next sequence number to emit (``MTProtoTransport/full`` only).
  private var sendSequence: UInt32 = 0

  /// Source of the random padding for ``MTProtoTransport/paddedIntermediate``.
  private var rng = SystemRandomNumberGenerator()

  public init(transport: MTProtoTransport) {
    self.transport = transport
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    let payload = unwrapOutboundIn(data)
    if transport.requiresWordAlignedPayload {
      precondition(
        payload.readableBytes % 4 == 0,
        "\(transport) requires a 4-byte-aligned MTProto payload, got \(payload.readableBytes) bytes"
      )
    }
    var out = context.channel.allocator.buffer(capacity: payload.readableBytes + 12)
    switch transport {
    case .abridged: encodeAbridged(payload, into: &out)
    case .intermediate: encodeIntermediate(payload, into: &out)
    case .paddedIntermediate: encodePaddedIntermediate(payload, into: &out)
    case .full: encodeFull(payload, into: &out)
    }
    context.write(wrapOutboundOut(out), promise: promise)
  }

  // MARK: Per-transport framing

  private func encodeAbridged(_ payload: ByteBuffer, into out: inout ByteBuffer) {
    let words = payload.readableBytes / 4
    if words < 0x7f {
      out.writeInteger(UInt8(words))
    } else {
      out.writeInteger(UInt8(0x7f))
      out.writeInteger(UInt8(truncatingIfNeeded: words), endianness: .little)
      out.writeInteger(UInt8(truncatingIfNeeded: words >> 8), endianness: .little)
      out.writeInteger(UInt8(truncatingIfNeeded: words >> 16), endianness: .little)
    }
    out.writeImmutableBuffer(payload)
  }

  private func encodeIntermediate(_ payload: ByteBuffer, into out: inout ByteBuffer) {
    out.writeInteger(UInt32(payload.readableBytes), endianness: .little)
    out.writeImmutableBuffer(payload)
  }

  private func encodePaddedIntermediate(_ payload: ByteBuffer, into out: inout ByteBuffer) {
    let padding = Int(rng.next() % 16)  // 0...15 random bytes
    out.writeInteger(UInt32(payload.readableBytes + padding), endianness: .little)
    out.writeImmutableBuffer(payload)
    for _ in 0..<padding {
      out.writeInteger(rng.next() as UInt8)
    }
  }

  private func encodeFull(_ payload: ByteBuffer, into out: inout ByteBuffer) {
    // length covers the length field itself, the seqno, the payload and the CRC.
    let length = UInt32(payload.readableBytes + 12)
    out.writeInteger(length, endianness: .little)
    out.writeInteger(sendSequence, endianness: .little)
    out.writeImmutableBuffer(payload)
    // CRC32 over the bytes written so far (length + seqno + payload).
    let crc = CRC32.checksum(of: out.readableBytesView)
    out.writeInteger(crc, endianness: .little)
    sendSequence &+= 1
  }
}
