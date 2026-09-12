/// Validation of incoming (server → client) message identifiers, per the
/// MTProto security guidelines
/// (<https://core.telegram.org/mtproto/security_guidelines#checking-msg-id>):
///
/// - **`msg_id` parity** — server message ids must be odd (`≡ 1 (mod 4)` for
///   replies, `≡ 3 (mod 4)` for server-initiated pushes).
/// - **Time window** — ids embedding a time outside `(now−300, now+30)`
///   (in *server* time; feed an offset-adjusted `now`) are rejected.
/// - **Replay / duplicates** — an id already seen in this session is dropped.
///
/// Unlike the client→server direction there is no salt check: the salt in a
/// server→client envelope is informational.
public struct MTProtoClientInboundValidator: Sendable {
  /// Why a message was rejected. The client never answers a bad server
  /// message; every rejection is a silent drop (plus a log line).
  public enum Rejection: Equatable, Sendable {
    /// Even `msg_id`, or one outside the acceptance time window.
    case badMessageID
    /// A `msg_id` already processed, or at/below the evicted replay window.
    case duplicate
  }

  /// How far in the past (seconds) a `msg_id` may be before it is rejected.
  public var pastToleranceSeconds: Int64
  /// How far in the future (seconds) a `msg_id` may be before it is rejected.
  public var futureToleranceSeconds: Int64
  /// Upper bound on the per-session set of remembered `msg_id`s.
  public var maxTrackedIDs: Int

  private var seen: Set<Int64> = []
  /// A min-heap retains the greatest ids regardless of arrival order.
  private var order: [UInt64] = []
  private var replayFloor: UInt64?

  public init(
    pastToleranceSeconds: Int64 = 300,
    futureToleranceSeconds: Int64 = 30,
    maxTrackedIDs: Int = 4096
  ) {
    self.pastToleranceSeconds = pastToleranceSeconds
    self.futureToleranceSeconds = futureToleranceSeconds
    self.maxTrackedIDs = maxTrackedIDs
  }

  /// Clears the replay window — called when the session is recreated.
  public mutating func reset() {
    seen.removeAll(keepingCapacity: true)
    order.removeAll(keepingCapacity: true)
    replayFloor = nil
  }

  /// Validates one inbound `msg_id` (top-level or container-nested; nested
  /// messages carry their own ids). Returns `nil` to process it, or why to
  /// drop it. The id is remembered for replay detection only when accepted.
  public mutating func validate(msgID: Int64, now: Int64) -> Rejection? {
    guard UInt64(bitPattern: msgID) % 2 == 1 else { return .badMessageID }
    let messageTime = Int64(UInt64(bitPattern: msgID) >> 32)
    if messageTime < now - pastToleranceSeconds { return .badMessageID }
    if messageTime > now + futureToleranceSeconds { return .badMessageID }
    let unsignedID = UInt64(bitPattern: msgID)
    if seen.contains(msgID) || replayFloor.map({ unsignedID <= $0 }) == true {
      return .duplicate
    }
    seen.insert(msgID)
    order.append(unsignedID)
    var index = order.count - 1
    while index > 0 {
      let parent = (index - 1) / 2
      guard order[index] < order[parent] else { break }
      order.swapAt(index, parent)
      index = parent
    }
    while order.count > max(1, maxTrackedIDs) {
      let oldest = order[0]
      replayFloor = oldest
      seen.remove(Int64(bitPattern: oldest))
      order[0] = order.removeLast()
      index = 0
      while index * 2 + 1 < order.count {
        let left = index * 2 + 1
        let right = left + 1
        let child = right < order.count && order[right] < order[left] ? right : left
        guard order[child] < order[index] else { break }
        order.swapAt(child, index)
        index = child
      }
    }
    return nil
  }
}
