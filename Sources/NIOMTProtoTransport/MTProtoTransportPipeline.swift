import NIOCore

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Everything needed to frame an MTProto connection over TCP: which transport,
/// whether to obfuscate it, and the inbound frame-size limit.
public struct MTProtoTransportConfiguration: Sendable {
  /// Optional transport-obfuscation settings.
  public struct Obfuscation: Sendable {
    /// An MTProxy secret (typically 16 bytes), or `nil` for plain obfuscation.
    public var secret: Data?
    /// The DC id to embed (MTProxy), or `nil`.
    public var dcId: Int16?

    public init(secret: Data? = nil, dcId: Int16? = nil) {
      self.secret = secret
      self.dcId = dcId
    }
  }

  /// The transport framing to use.
  public var transport: MTProtoTransport
  /// Obfuscation settings, or `nil` for a clear-text transport.
  public var obfuscation: Obfuscation?
  /// The largest inbound frame the decoder will accept.
  public var maximumFrameLength: Int

  public init(
    transport: MTProtoTransport,
    obfuscation: Obfuscation? = nil,
    maximumFrameLength: Int = 1 << 24
  ) {
    self.transport = transport
    self.obfuscation = obfuscation
    self.maximumFrameLength = maximumFrameLength
  }
}

extension MTProtoTransportConfiguration {
  /// Builds the transport handlers in head-to-tail (socket-to-application)
  /// order: obfuscation/preamble, then the frame decoder, then the encoder.
  ///
  /// Add them with `pipeline.addHandlers(...)` and place your MTProto message
  /// handlers after them; they will then exchange plain `ByteBuffer` payloads.
  ///
  /// - Throws: ``MTProtoTransportError/obfuscationUnsupported(_:)`` when
  ///   obfuscation is requested for ``MTProtoTransport/full``.
  public func makeHandlers() throws -> [any ChannelHandler] {
    if obfuscation != nil, transport.obfuscationTag == nil {
      throw MTProtoTransportError.obfuscationUnsupported(transport)
    }
    var handlers: [any ChannelHandler] = []
    if let obfuscation {
      handlers.append(
        MTProtoObfuscationHandler(
          transport: transport, secret: obfuscation.secret, dcId: obfuscation.dcId))
    } else {
      handlers.append(MTProtoClearPreambleHandler(transport: transport))
    }
    handlers.append(
      ByteToMessageHandler(
        MTProtoFrameDecoder(transport: transport, maximumFrameLength: maximumFrameLength)))
    handlers.append(MTProtoFrameEncoder(transport: transport))
    return handlers
  }
}

extension ChannelPipeline {
  /// Installs the MTProto transport handlers described by `configuration` at
  /// the head of the pipeline.
  ///
  /// After they are added, the pipeline speaks plain MTProto payloads: inbound
  /// `ByteBuffer`s are de-obfuscated and de-framed message bodies, and outbound
  /// `ByteBuffer`s are framed (and obfuscated) before hitting the socket.
  public func addMTProtoTransportHandlers(
    _ configuration: MTProtoTransportConfiguration
  ) -> EventLoopFuture<Void> {
    // Build and install the handlers on the event loop so the (non-Sendable)
    // handler instances never cross a concurrency boundary.
    eventLoop.submit {
      try self.syncOperations.addHandlers(configuration.makeHandlers())
    }
  }
}
