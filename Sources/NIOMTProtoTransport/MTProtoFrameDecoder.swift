import MTProtoUtils
import NIOCore

/// Decodes the inbound TCP byte stream of an MTProto connection into the
/// individual MTProto payloads carried by the configured ``MTProtoTransport``.
///
/// The decoder strips the transport envelope (length prefix, sequence number,
/// CRC32) and emits each payload as a `ByteBuffer`. It operates on a stream
/// that has already been de-obfuscated — when obfuscation is in use, the
/// ``MTProtoObfuscationHandler`` sits closer to the socket and decrypts bytes
/// before they reach this decoder.
///
/// > Note: For ``MTProtoTransport/paddedIntermediate`` the emitted payload
/// > still contains the 0–15 trailing random padding bytes, since their count
/// > is not recoverable from the transport framing alone. The MTProto message
/// > layer determines the real payload length from the message structure and
/// > ignores the trailing padding.
public struct MTProtoFrameDecoder: ByteToMessageDecoder {
  public typealias InboundOut = ByteBuffer

  /// The transport whose framing is being decoded.
  public let transport: MTProtoTransport

  /// The largest frame length the decoder will accept before treating the
  /// stream as corrupt. Guards against unbounded buffering / allocation.
  public let maximumFrameLength: Int

  /// The next expected sequence number (``MTProtoTransport/full`` only).
  private var receiveSequence: UInt32 = 0

  public init(transport: MTProtoTransport, maximumFrameLength: Int = 1 << 24) {
    self.transport = transport
    self.maximumFrameLength = maximumFrameLength
  }

  public mutating func decode(
    context: ChannelHandlerContext, buffer: inout ByteBuffer
  ) throws -> DecodingState {
    switch transport {
    case .abridged: return try decodeAbridged(context: context, buffer: &buffer)
    case .intermediate, .paddedIntermediate:
      return try decodeIntermediate(context: context, buffer: &buffer)
    case .full: return try decodeFull(context: context, buffer: &buffer)
    }
  }

  // MARK: Abridged

  private mutating func decodeAbridged(
    context: ChannelHandlerContext, buffer: inout ByteBuffer
  ) throws -> DecodingState {
    let start = buffer.readerIndex
    guard let first: UInt8 = buffer.getInteger(at: start, as: UInt8.self) else {
      return .needMoreData
    }
    let headerLength: Int
    let payloadLength: Int
    if first == 0x7f || first == 0xff {
      // Long form: 0x7f (or 0xff with the quick-ack bit) + 3-byte LE word count.
      guard buffer.readableBytes >= 4 else { return .needMoreData }
      let b0 = buffer.getInteger(at: start + 1, as: UInt8.self)!
      let b1 = buffer.getInteger(at: start + 2, as: UInt8.self)!
      let b2 = buffer.getInteger(at: start + 3, as: UInt8.self)!
      let words = Int(b0) | Int(b1) << 8 | Int(b2) << 16
      headerLength = 4
      payloadLength = words * 4
    } else {
      // Short form: a single byte holding the word count (top bit = quick-ack).
      headerLength = 1
      payloadLength = Int(first & 0x7f) * 4
    }
    guard payloadLength <= maximumFrameLength else {
      throw MTProtoTransportError.invalidFrameLength(payloadLength)
    }
    guard buffer.readableBytes >= headerLength + payloadLength else {
      return .needMoreData
    }
    buffer.moveReaderIndex(forwardBy: headerLength)
    let payload = buffer.readSlice(length: payloadLength)!
    try emit(payload, context: context)
    return .continue
  }

  // MARK: Intermediate / Padded intermediate

  private mutating func decodeIntermediate(
    context: ChannelHandlerContext, buffer: inout ByteBuffer
  ) throws -> DecodingState {
    let start = buffer.readerIndex
    guard let lengthField = buffer.getInteger(at: start, endianness: .little, as: UInt32.self)
    else {
      return .needMoreData
    }
    // The top bit, if set, is the quick-ack marker rather than a length bit.
    let payloadLength = Int(lengthField & 0x7fff_ffff)
    guard payloadLength <= maximumFrameLength else {
      throw MTProtoTransportError.invalidFrameLength(payloadLength)
    }
    guard buffer.readableBytes >= 4 + payloadLength else { return .needMoreData }
    buffer.moveReaderIndex(forwardBy: 4)
    let payload = buffer.readSlice(length: payloadLength)!
    try emit(payload, context: context)
    return .continue
  }

  // MARK: Full

  private mutating func decodeFull(
    context: ChannelHandlerContext, buffer: inout ByteBuffer
  ) throws -> DecodingState {
    let start = buffer.readerIndex
    guard let length32 = buffer.getInteger(at: start, endianness: .little, as: UInt32.self) else {
      return .needMoreData
    }
    let length = Int(length32)
    // length covers the length field, the seqno, the payload and the CRC.
    guard length >= 12, length <= maximumFrameLength else {
      throw MTProtoTransportError.invalidFrameLength(length)
    }
    guard buffer.readableBytes >= length else { return .needMoreData }

    // CRC32 is computed over everything but the trailing CRC word itself.
    let checked = buffer.getBytes(at: start, length: length - 4)!
    let expected = CRC32.checksum(of: checked)
    let found = buffer.getInteger(at: start + length - 4, endianness: .little, as: UInt32.self)!
    guard expected == found else {
      throw MTProtoTransportError.crcMismatch(expected: expected, found: found)
    }
    let sequence = buffer.getInteger(at: start + 4, endianness: .little, as: UInt32.self)!
    guard sequence == receiveSequence else {
      throw MTProtoTransportError.sequenceMismatch(expected: receiveSequence, found: sequence)
    }
    receiveSequence &+= 1

    let payload = buffer.getSlice(at: start + 8, length: length - 12)!
    buffer.moveReaderIndex(forwardBy: length)
    // Full transport frames carry their own CRC, so the bare 4-byte negative
    // error codes used by the other transports do not apply here.
    context.fireChannelRead(wrapInboundOut(payload))
    return .continue
  }

  // MARK: Helpers

  /// Emits a decoded payload, first translating the bare 4-byte negative error
  /// codes (`-404`, `-429`, …) the lighter transports use into a thrown
  /// ``MTProtoTransportError/serverError(code:)``.
  private func emit(_ payload: ByteBuffer, context: ChannelHandlerContext) throws {
    if payload.readableBytes == 4 {
      let code = payload.getInteger(at: payload.readerIndex, endianness: .little, as: Int32.self)!
      if code < 0 {
        throw MTProtoTransportError.serverError(code: 0 &- code)
      }
    }
    context.fireChannelRead(wrapInboundOut(payload))
  }
}
