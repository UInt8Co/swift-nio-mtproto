import Crypto
import NIOCore

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// A channel handler implementing MTProto transport obfuscation.
///
/// Placed at the head of the pipeline (closest to the socket), it:
/// 1. on `channelActive`, generates the 64-byte obfuscation header and writes
///    it before anything else;
/// 2. encrypts every outbound byte with the connection's AES-256-CTR
///    encryption keystream; and
/// 3. decrypts every inbound byte with the decryption keystream,
///
/// so the framing codecs above it see a plain, de-obfuscated stream. See
/// ``MTProtoObfuscation`` for the handshake details.
public final class MTProtoObfuscationHandler: ChannelDuplexHandler {
  public typealias InboundIn = ByteBuffer
  public typealias InboundOut = ByteBuffer
  public typealias OutboundIn = ByteBuffer
  public typealias OutboundOut = ByteBuffer

  private let transport: MTProtoTransport
  private let secret: Data?
  private let dcId: Int16?
  /// When set, used instead of fresh randomness so tests can pin the payload.
  private let fixedInitPayload: [UInt8]?
  /// `false` for a handler built from pre-derived keystreams (the accepting end
  /// of the handshake): it neither generates nor sends an init header.
  private let initiatesHandshake: Bool

  private var encrypt: AESCTRStream?
  private var decrypt: AESCTRStream?

  public init(transport: MTProtoTransport, secret: Data? = nil, dcId: Int16? = nil) {
    self.transport = transport
    self.secret = secret
    self.dcId = dcId
    self.fixedInitPayload = nil
    self.initiatesHandshake = true
  }

  /// Test seam: build a handler whose handshake uses a fixed init payload.
  init(transport: MTProtoTransport, secret: Data?, dcId: Int16?, fixedInitPayload: [UInt8]) {
    self.transport = transport
    self.secret = secret
    self.dcId = dcId
    self.fixedInitPayload = fixedInitPayload
    self.initiatesHandshake = true
  }

  /// Builds a handler for the *accepting* end of the obfuscation handshake, from
  /// the keystreams already derived from the initiator's init (see
  /// ``MTProtoObfuscation/acceptHandshake(received:secret:)``). It does not emit
  /// an init header; it only decrypts inbound and encrypts outbound bytes.
  public init(encrypt: AESCTRStream, decrypt: AESCTRStream, transport: MTProtoTransport) {
    self.transport = transport
    self.secret = nil
    self.dcId = nil
    self.fixedInitPayload = nil
    self.initiatesHandshake = false
    self.encrypt = encrypt
    self.decrypt = decrypt
  }

  public func channelActive(context: ChannelHandlerContext) {
    if !initiatesHandshake {
      // Keystreams are already set; nothing to send.
      context.fireChannelActive()
      return
    }
    do {
      let handshake: MTProtoObfuscation.Handshake
      if let fixedInitPayload {
        handshake = try MTProtoObfuscation.makeHandshake(
          transport: transport, secret: secret, dcId: dcId, initPayload: fixedInitPayload)
      } else {
        var rng = SystemRandomNumberGenerator()
        handshake = try MTProtoObfuscation.makeHandshake(
          transport: transport, secret: secret, dcId: dcId, using: &rng)
      }
      self.encrypt = handshake.encrypt
      self.decrypt = handshake.decrypt

      var header = context.channel.allocator.buffer(capacity: handshake.header.count)
      header.writeBytes(handshake.header)
      // The header is the final wire bytes; write it directly past this handler
      // (it must not be re-encrypted by `write`).
      context.writeAndFlush(wrapOutboundOut(header), promise: nil)
      context.fireChannelActive()
    } catch {
      context.fireErrorCaught(error)
      context.close(promise: nil)
    }
  }

  public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
    let buffer = unwrapInboundIn(data)
    guard decrypt != nil, buffer.readableBytes > 0 else {
      context.fireChannelRead(data)
      return
    }
    let plaintext = Self.apply(&decrypt!, to: buffer, allocator: context.channel.allocator)
    context.fireChannelRead(wrapInboundOut(plaintext))
  }

  public func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?)
  {
    let buffer = unwrapOutboundIn(data)
    guard encrypt != nil, buffer.readableBytes > 0 else {
      context.write(data, promise: promise)
      return
    }
    let ciphertext = Self.apply(&encrypt!, to: buffer, allocator: context.channel.allocator)
    context.write(wrapOutboundOut(ciphertext), promise: promise)
  }

  /// Runs `buffer`'s readable bytes through `stream` into a new buffer: one
  /// allocation, and one pass that reads the input and writes the output.
  ///
  /// Not in place, because a buffer that arrives through the pipeline is never
  /// this handler's alone: the `NIOAny` it came in still holds it, and a read
  /// buffer also belongs to the channel's receive pool, which reuses it for
  /// the next read when nobody kept it. Writing to it would have NIO copy all
  /// of it aside first.
  private static func apply(
    _ stream: inout AESCTRStream, to buffer: ByteBuffer, allocator: ByteBufferAllocator
  ) -> ByteBuffer {
    let count = buffer.readableBytes
    var out = allocator.buffer(capacity: count)
    buffer.withUnsafeReadableBytes { input in
      _ = out.writeWithUnsafeMutableBytes(minimumWritableBytes: count) { output in
        stream.apply(input, into: output)
        return count
      }
    }
    return out
  }
}
