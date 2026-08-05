/// An API-level `rpc_error` returned for an invoked query, surfaced as a
/// thrown Swift error (`FLOOD_WAIT_X`, `USER_ID_INVALID`, …).
public struct MTProtoRPCError: Error, Equatable, Sendable {
  public let code: Int32
  public let message: String

  public init(code: Int32, message: String) {
    self.code = code
    self.message = message
  }
}

/// Session/connection-level client errors.
public enum MTProtoClientError: Error, Equatable, Sendable {
  /// An operation was attempted before `connect()` (no channel).
  case notConnected
  /// The connection was closed (or lost) with queries still in flight.
  case connectionClosed
  /// The per-request time budget elapsed without an `rpc_result`.
  case timeout
  /// The server sent a transport-level protocol error frame (a 4-byte
  /// negative int), e.g. `-404` for "auth key not found" — discard the
  /// resumed key and re-handshake.
  case protocolError(Int32)
  /// The server rejected a message with a non-recoverable
  /// `bad_msg_notification` code (18/19/32–35/64): a client bug, fatal for
  /// the connection.
  case fatalBadMessage(code: Int32)
}
