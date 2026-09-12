/// Errors surfaced by the MTProto transport layer.
public enum MTProtoTransportError: Error, Equatable, Sendable, CustomStringConvertible {
  /// A frame's CRC32 (``MTProtoTransport/full``) did not match the computed
  /// value: the stream is corrupt or out of sync.
  case crcMismatch(expected: UInt32, found: UInt32)

  /// A ``MTProtoTransport/full`` frame carried an unexpected sequence number.
  case sequenceMismatch(expected: UInt32, found: UInt32)

  /// A frame announced a length that is implausible (negative, zero where a
  /// payload is required, or larger than ``maximumFrameLength``).
  case invalidFrameLength(Int)

  /// The server returned a transport-level error instead of a message. These
  /// arrive as a 4-byte frame whose body is a negative little-endian `int32`;
  /// `code` is its absolute value (e.g. `404` = auth key not found,
  /// `429` = transport flood, `444` = invalid DC).
  case serverError(code: Int32)

  /// Obfuscation was requested for ``MTProtoTransport/full``, which has no
  /// protocol identifier and therefore cannot be obfuscated.
  case obfuscationUnsupported(MTProtoTransport)

  /// An accepted connection's obfuscation init named no known transport (see
  /// ``MTProtoObfuscation/acceptHandshake(received:secret:)``).
  case unrecognizedTransport(tag: UInt32)

  /// The accepting peer did not provide an exact 64-byte obfuscation header.
  case invalidObfuscationHeaderLength(Int)

  public var description: String {
    switch self {
    case .crcMismatch(let expected, let found):
      return
        "MTProtoTransportError.crcMismatch: expected 0x\(String(expected, radix: 16)), found 0x\(String(found, radix: 16))"
    case .sequenceMismatch(let expected, let found):
      return "MTProtoTransportError.sequenceMismatch: expected \(expected), found \(found)"
    case .invalidFrameLength(let length):
      return "MTProtoTransportError.invalidFrameLength: \(length)"
    case .serverError(let code):
      return "MTProtoTransportError.serverError: \(code)"
    case .obfuscationUnsupported(let transport):
      return "MTProtoTransportError.obfuscationUnsupported: \(transport)"
    case .unrecognizedTransport(let tag):
      return "MTProtoTransportError.unrecognizedTransport: 0x\(String(tag, radix: 16))"
    case .invalidObfuscationHeaderLength(let length):
      return "MTProtoTransportError.invalidObfuscationHeaderLength: \(length)"
    }
  }
}
