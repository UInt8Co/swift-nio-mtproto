/// The MTProto TCP transport protocols.
///
/// MTProto messages are exchanged over a raw TCP stream wrapped in one of
/// several *transport* envelopes, documented at
/// <https://core.telegram.org/mtproto/mtproto-transports>. Each transport
/// frames the opaque MTProto payload differently (length prefixes, padding,
/// sequence numbers, CRC32) but they all carry the same payloads.
///
/// This type only describes *which* transport is in use; the actual wire
/// framing lives in ``MTProtoFrameEncoder`` / ``MTProtoFrameDecoder`` and the
/// obfuscation layer in ``MTProtoObfuscationHandler``.
public enum MTProtoTransport: Sendable, Hashable, CaseIterable {
  /// The lightest transport: a 1- or 4-byte length prefix and no other
  /// overhead. Identified by the single magic byte `0xef`.
  case abridged

  /// A 4-byte little-endian length prefix. Identified by the magic word
  /// `0xeeeeeeee`.
  case intermediate

  /// Like ``intermediate`` but each frame is followed by 0–15 random padding
  /// bytes (the length prefix counts the padding). Used together with
  /// obfuscation to defeat traffic analysis. Magic word `0xdddddddd`.
  case paddedIntermediate

  /// The original transport: `length`, `seqno`, payload and a trailing
  /// `CRC32`. Has no magic prefix and cannot be obfuscated.
  case full

  // MARK: Clear-stream preamble

  /// The bytes a client must send once, before any frame, when the transport
  /// is **not** obfuscated. (When obfuscated, the protocol is identified by
  /// ``obfuscationTag`` embedded in the obfuscation header instead.)
  ///
  /// ``full`` has no preamble and returns an empty array.
  public var clearPreamble: [UInt8] {
    switch self {
    case .abridged: return [0xef]
    case .intermediate: return [0xee, 0xee, 0xee, 0xee]
    case .paddedIntermediate: return [0xdd, 0xdd, 0xdd, 0xdd]
    case .full: return []
    }
  }

  /// The 4-byte protocol identifier written at offset 56 of the obfuscation
  /// init payload. `nil` for ``full``, which is not compatible with
  /// obfuscation.
  ///
  /// The values are byte-palindromes (`0xefefefef`, `0xeeeeeeee`,
  /// `0xdddddddd`), so their little-endian and big-endian encodings coincide.
  public var obfuscationTag: UInt32? {
    switch self {
    case .abridged: return 0xefef_efef
    case .intermediate: return 0xeeee_eeee
    case .paddedIntermediate: return 0xdddd_dddd
    case .full: return nil
    }
  }

  /// Whether MTProto payloads handed to this transport must be a multiple of
  /// four bytes long. All MTProto messages already satisfy this; the encoder
  /// enforces it as a precondition for the transports that require it.
  public var requiresWordAlignedPayload: Bool {
    switch self {
    case .abridged, .intermediate, .full: return true
    case .paddedIntermediate: return false
    }
  }
}
