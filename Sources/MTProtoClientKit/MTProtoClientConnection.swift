import MTProtoBaseSchema
import MTProtoCrypto
import NIOMTProtoEncryption
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Session-level configuration for one MTProto client connection.
public struct MTProtoClientConfiguration: Sendable {
  /// The server's RSA public key — the trust anchor: the handshake verifies the
  /// offered fingerprint against it and encrypts to it.
  public var rsaPublicKey: RSAPublicKey
  /// The trusted DH group; the handshake rejects any other.
  public var dhParameters: MTProtoDHParameters
  /// The DC id to embed in `p_q_inner_data_dc`, or nil for the plain
  /// constructor.
  public var dcID: Int32?
  /// Resume a previously negotiated session (auth key + stored salt)
  /// instead of handshaking. The server answers the first message with
  /// `new_session_created`; a stale salt recovers via `bad_server_salt`.
  public var resumeSession: MTProtoStoredSession?
  /// The idle `ping_delay_disconnect` cadence; nil disables the timer.
  public var pingInterval: Duration?
  /// Per-`invoke` time budget; nil waits indefinitely.
  public var requestTimeout: Duration?
  /// How long `connect()` waits for the handshake (or resume) to make the
  /// session usable before failing — guards against a server that accepts
  /// the TCP connection but never completes the handshake. Nil waits forever.
  public var connectTimeout: Duration?
  /// Fired when a fresh handshake completes, with the keys to persist for
  /// later ``resumeSession`` use.
  public var onSessionEstablished: (@Sendable (MTProtoSessionKeys) -> Void)?
  /// Server-initiated content the session layer doesn't consume — API
  /// updates, pushed down the connection outside any `rpc_result`. Receives
  /// the boxed message body.
  public var onUnhandledMessage: (@Sendable (Data) -> Void)?
  public var log: (@Sendable (String) -> Void)?

  public init(
    rsaPublicKey: RSAPublicKey,
    dhParameters: MTProtoDHParameters = .telegram2048,
    dcID: Int32? = nil,
    resumeSession: MTProtoStoredSession? = nil,
    pingInterval: Duration? = .seconds(30),
    requestTimeout: Duration? = .seconds(30),
    connectTimeout: Duration? = .seconds(30),
    onSessionEstablished: (@Sendable (MTProtoSessionKeys) -> Void)? = nil,
    onUnhandledMessage: (@Sendable (Data) -> Void)? = nil,
    log: (@Sendable (String) -> Void)? = nil
  ) {
    self.rsaPublicKey = rsaPublicKey
    self.dhParameters = dhParameters
    self.dcID = dcID
    self.resumeSession = resumeSession
    self.pingInterval = pingInterval
    self.requestTimeout = requestTimeout
    self.connectTimeout = connectTimeout
    self.onSessionEstablished = onSessionEstablished
    self.onUnhandledMessage = onUnhandledMessage
    self.log = log
  }
}

/// The MTProto *client session layer* for one connection: drives the
/// handshake (or resume), correlates queries with `rpc_result`s by
/// `req_msg_id`, and implements the rules a well-behaved client owes the
/// server — inbound `msg_id` validation and dedup,
/// container/`gzip_packed` parsing, salt adoption (`bad_server_salt`,
/// `new_session_created`, `future_salts`), `bad_msg_notification` reactions,
/// batched `msgs_ack`, and the `ping_delay_disconnect` liveness timer.
///
/// Transport-agnostic: it consumes raw MTProto payloads (as framed by
/// `NIOMTProtoTransport`) via ``handleInbound(_:)`` and writes payloads
/// through the sink given to ``channelActive(write:close:)``.
/// ``MTProtoClient`` wires it to a NIO pipeline.
public actor MTProtoClientConnection {
  private let configuration: MTProtoClientConfiguration
  private var crypto: MTProtoClientSessionCrypto
  private var validator = MTProtoClientInboundValidator()
  private var log: (@Sendable (String) -> Void)? { configuration.log }

  /// Writes one raw payload to the transport (thread-safe channel write).
  private var write: (@Sendable (Data) -> Void)?
  /// Requests the transport be closed (fatal protocol conditions).
  private var closeTransport: (@Sendable () -> Void)?

  private enum Phase {
    case idle
    case handshaking
    case ready
    case closed(MTProtoClientError)
  }
  private var phase: Phase = .idle
  /// Callers parked in ``waitUntilReady(timeout:)``, keyed by a monotonic id
  /// so a per-waiter timeout can resolve exactly its own continuation.
  private struct ReadyWaiter {
    var continuation: CheckedContinuation<Void, Error>
  }
  private var readyWaiters: [UInt64: ReadyWaiter] = [:]
  private var nextWaiterID: UInt64 = 0

  /// One in-flight query, keyed by its current `msg_id`. The body is kept so
  /// `bad_server_salt` / `bad_msg_notification` can resend it under a fresh
  /// id.
  private struct PendingQuery {
    var body: Data
    var continuation: CheckedContinuation<Data, Error>
  }
  private var pending: [Int64: PendingQuery] = [:]
  /// One in-flight explicit `ping`, keyed by `ping_id`.
  private struct PendingPing {
    var continuation: CheckedContinuation<Void, Error>
  }
  private var pendingPings: [Int64: PendingPing] = [:]
  private var nextPingID: Int64 = 1

  /// Server content-message ids awaiting a batched `msgs_ack`.
  private var pendingAcks: [Int64] = []
  /// Whether a batched `msgs_ack` is armed, and which arming is current: a
  /// timer is orphaned by a newer generation rather than cancelled.
  private var ackFlushArmed = false
  private var ackFlushGeneration: UInt64 = 0
  /// Set once the ping loop starts. It ends itself on close, and a closed
  /// connection never becomes ready again, so it is never unset.
  private var pingLoopRunning = false
  /// When the current salt stops being valid (0 = unknown/no expiry known);
  /// learned from `future_salts`, drives the proactive refresh.
  private var saltValidUntil: Int64 = 0
  /// Whether the server-time offset has been established. A fresh handshake
  /// sets it from `server_DH_inner_data`; a resumed session learns it from
  /// its first inbound server message.
  private var hasAnchoredServerTime = false

  public init(configuration: MTProtoClientConfiguration) {
    self.configuration = configuration
    self.crypto = MTProtoClientSessionCrypto(
      rsaKey: configuration.rsaPublicKey,
      dhParameters: configuration.dhParameters,
      dcID: configuration.dcID)
  }

  // MARK: - Channel lifecycle (called by the channel handler)

  /// The transport is up: resume the stored session, or start the handshake.
  public func channelActive(
    write: @escaping @Sendable (Data) -> Void,
    close: @escaping @Sendable () -> Void
  ) {
    self.write = write
    self.closeTransport = close
    if let stored = configuration.resumeSession {
      crypto.resumeSession(authKey: stored.authKey, serverSalt: stored.serverSalt)
      log?("client: resumed session (auth_key_id=\(crypto.authKeyID))")
      becomeReady()
    } else {
      phase = .handshaking
      log?("client: starting auth-key handshake")
      write(crypto.startHandshake())
    }
  }

  /// The transport went away: everything in flight fails.
  public func channelInactive() {
    failAll(.connectionClosed)
  }

  /// Processes one inbound transport payload.
  public func handleInbound(_ payload: Data) async {
    do {
      switch try crypto.processInbound(payload) {
      case .handshakeSend(let next):
        write?(next)
      case .established(let keys):
        log?("client: auth key established (auth_key_id=\(keys.authKeyID))")
        // The handshake already derived the server-time offset from
        // server_DH_inner_data; no bootstrap from the first message needed.
        hasAnchoredServerTime = true
        configuration.onSessionEstablished?(keys)
        becomeReady()
      case .message(let message):
        handleMessage(message)
      case .protocolError(let code):
        log?("client: transport protocol error \(code)")
        failAll(.protocolError(code))
        closeTransport?()
      }
    } catch let error as MTProtoClientSessionError {
      if case .handshakeRejected(let reason) = error {
        log?("client: handshake failed: \(reason)")
        failAll(.connectionClosed)
        closeTransport?()
      } else {
        // Malformed or unauthenticated payload: drop it, keep the connection.
        log?("client: dropping inbound payload: \(error)")
      }
    } catch {
      log?("client: dropping inbound payload: \(error)")
    }
  }

  // MARK: - Public API

  /// Suspends until the session is usable (handshake finished / resumed). If
  /// `timeout` is non-nil and it elapses first, throws
  /// ``MTProtoClientError/timeout`` — guarding against a server that accepts
  /// the socket but never completes the handshake.
  ///
  /// The timeout is implemented inside the actor (a per-waiter task that
  /// resolves this exact continuation), not by racing tasks in a
  /// `TaskGroup`: `withCheckedContinuation` is not cancellation-aware, so a
  /// group would await a stuck child forever on scope exit.
  public func waitUntilReady(timeout: Duration? = nil) async throws {
    switch phase {
    case .ready:
      return
    case .closed(let error):
      throw error
    case .idle, .handshaking:
      let id = nextWaiterID
      nextWaiterID += 1
      try await withCheckedThrowingContinuation { continuation in
        readyWaiters[id] = ReadyWaiter(continuation: continuation)
        // The deadline runs itself out rather than being cancelled: cancelling
        // a `Task.sleep` leaks (swiftlang/swift#60441), and
        // `timeOutReadyWaiter` does nothing once the waiter is gone.
        if let timeout {
          Task { [weak self] in
            try? await Task.sleep(for: timeout)
            await self?.timeOutReadyWaiter(id)
          }
        }
      }
    }
  }

  /// The authenticated transport binding, only while the connection is ready.
  public func sessionBinding() -> MTProtoSessionBinding? {
    guard case .ready = phase else { return nil }
    return MTProtoSessionBinding(authKeyID: crypto.authKeyID, sessionID: crypto.sessionID)
  }

  private func timeOutReadyWaiter(_ id: UInt64) {
    guard let waiter = readyWaiters.removeValue(forKey: id) else { return }
    waiter.continuation.resume(throwing: MTProtoClientError.timeout)
  }

  /// Sends one boxed query and returns the boxed result bytes from its
  /// `rpc_result` (throwing ``MTProtoRPCError`` for an `rpc_error` result).
  public func invoke(_ queryBody: Data) async throws -> Data {
    try await waitUntilReady()
    return try await withCheckedThrowingContinuation { continuation in
      do {
        let msgID = try sendMessage(body: queryBody, contentRelated: true)
        pending[msgID] = PendingQuery(body: queryBody, continuation: continuation)
        armTimeout(for: msgID)
      } catch {
        continuation.resume(throwing: error)
      }
    }
  }

  /// Arms the per-query timeout for `msgID`, keyed to the id the query lives
  /// under, so a resend re-arms for its new id (``resendQuery(_:)``) and the
  /// deadline left over from the old one finds nothing and does nothing.
  private func armTimeout(for msgID: Int64) {
    guard let timeout = configuration.requestTimeout else { return }
    Task { [weak self] in
      try? await Task.sleep(for: timeout)
      await self?.timeOutQuery(msgID)
    }
  }

  /// One explicit `ping` round-trip (liveness probe / test hook). Bounded by
  /// `requestTimeout` so a lost `pong` on an otherwise-live connection fails
  /// rather than hanging forever.
  public func ping() async throws {
    try await waitUntilReady()
    let pingID = nextPingID
    nextPingID += 1
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
      do {
        let body = TL.Ping(pingId: pingID).tlSerialized()
        _ = try sendMessage(body: body, contentRelated: false)
        pendingPings[pingID] = PendingPing(continuation: continuation)
        armPingTimeout(for: pingID)
      } catch {
        continuation.resume(throwing: error)
      }
    }
  }

  private func armPingTimeout(for pingID: Int64) {
    guard let timeout = configuration.requestTimeout else { return }
    Task { [weak self] in
      try? await Task.sleep(for: timeout)
      await self?.timeOutPing(pingID)
    }
  }

  private func timeOutPing(_ pingID: Int64) {
    guard let ping = pendingPings.removeValue(forKey: pingID) else { return }
    ping.continuation.resume(throwing: MTProtoClientError.timeout)
  }

  /// Best-effort graceful teardown: tells the server to drop the session
  /// (`destroy_session`) before the transport closes.
  public func prepareDisconnect() {
    guard case .ready = phase else { return }
    flushAcks()
    _ = try? sendMessage(
      body: TL.DestroySession(sessionId: crypto.sessionID).tlSerialized(),
      contentRelated: false)
  }

  // MARK: - Ready / failure transitions

  private func becomeReady() {
    // Only the initial idle/handshaking → ready transition counts. A late
    // inbound message (processed after failAll ordered a close but before
    // channelInactive arrives) must not resurrect a .closed connection, and a
    // stray second establish must not re-fire the waiters/ping loop.
    switch phase {
    case .idle, .handshaking:
      break
    case .ready, .closed:
      return
    }
    phase = .ready
    validator.reset()
    let waiters = readyWaiters
    readyWaiters.removeAll()
    for (_, waiter) in waiters {
      waiter.continuation.resume()
    }
    startPingLoopIfNeeded()
  }

  private func failAll(_ error: MTProtoClientError) {
    if case .closed = phase { return }
    phase = .closed(error)
    let waiters = readyWaiters
    readyWaiters.removeAll()
    for (_, waiter) in waiters {
      waiter.continuation.resume(throwing: error)
    }
    for (_, query) in pending {
      query.continuation.resume(throwing: error)
    }
    pending.removeAll()
    for (_, ping) in pendingPings {
      ping.continuation.resume(throwing: error)
    }
    pendingPings.removeAll()
    // Nothing here cancels a timer: the ping loop reads the phase on its next
    // wake, and the armed ack flush is orphaned by the generation bump.
    ackFlushArmed = false
    ackFlushGeneration &+= 1
  }

  // MARK: - Sending

  /// Seals and writes one message, returning its assigned `msg_id`.
  private func sendMessage(body: Data, contentRelated: Bool) throws -> Int64 {
    guard let write else { throw MTProtoClientError.notConnected }
    let (msgID, payload) = try crypto.encrypt(body: body, contentRelated: contentRelated)
    write(payload)
    return msgID
  }

  /// Seals and writes several messages as one `msg_container`.
  private func sendContainer(_ messages: [(body: Data, contentRelated: Bool)]) throws {
    guard let write else { throw MTProtoClientError.notConnected }
    let (_, payload) = try crypto.encryptContainer(messages)
    write(payload)
  }

  /// Re-sends a pending query under a fresh `msg_id` (after
  /// `bad_server_salt` / a recoverable `bad_msg_notification` /
  /// `new_session_created` loss recovery).
  private func resendQuery(_ oldMsgID: Int64) {
    guard let query = pending.removeValue(forKey: oldMsgID) else { return }
    do {
      let newMsgID = try sendMessage(body: query.body, contentRelated: true)
      log?("client: resent query #\(oldMsgID) as #\(newMsgID)")
      pending[newMsgID] = query
      // The deadline the old id armed is left to expire and find nothing.
      armTimeout(for: newMsgID)
    } catch {
      query.continuation.resume(throwing: error)
    }
  }

  private func timeOutQuery(_ msgID: Int64) {
    guard let query = pending.removeValue(forKey: msgID) else { return }
    log?("client: query #\(msgID) timed out")
    query.continuation.resume(throwing: MTProtoClientError.timeout)
  }

  /// The in-flight query ids in ascending *unsigned* (msg_id) order — the
  /// order they were actually sent (msg_id = unixtime << 32).
  private func pendingKeysAscending() -> [Int64] {
    pending.keys.sorted { UInt64(bitPattern: $0) < UInt64(bitPattern: $1) }
  }

  // MARK: - Inbound messages

  private func handleMessage(_ message: MTProtoPlainMessage) {
    // On a *resumed* session the server-time offset is unknown (it is not
    // persisted with the auth key), so bootstrap it from the first inbound
    // (authenticated) server msg_id before the window check — otherwise a
    // clock-skewed client would reject every server message and never learn
    // the offset, leaving the resumed session permanently dead. A fresh
    // handshake already anchored the offset from server_DH_inner_data.
    if !hasAnchoredServerTime {
      crypto.updateTimeOffset(fromServerMsgID: message.msgID)
      hasAnchoredServerTime = true
    }
    if let rejection = validator.validate(msgID: message.msgID, now: crypto.adjustedNow) {
      log?("client: dropping server message \(message.msgID): \(rejection)")
      return
    }
    var remainingInflatedBytes = 1 << 24
    handleBody(
      message.body, msgID: message.msgID, seqNo: message.seqNo,
      envelopeMsgID: message.msgID, recordAck: true, depth: 0,
      remainingInflatedBytes: &remainingInflatedBytes)
  }

  /// Processes one message body. `msgID`/`seqNo` are the message's own
  /// (container leaves carry their own); `envelopeMsgID` is the top-level
  /// server message id, used to re-anchor the time estimate. `recordAck` is
  /// true only for genuine wire messages (top-level and container leaves);
  /// the `gzip_packed` re-entry passes false so the same id is not acked
  /// twice.
  private func handleBody(
    _ body: Data, msgID: Int64, seqNo: Int32, envelopeMsgID: Int64, recordAck: Bool,
    depth: Int, remainingInflatedBytes: inout Int
  ) {
    guard depth < 32 else {
      log?("client: dropping excessively nested message #\(msgID)")
      return
    }
    // Every content-related server message must be acknowledged (batched).
    if recordAck, seqNo % 2 == 1 {
      pendingAcks.append(msgID)
      scheduleAckFlush()
    }

    var reader = TLReader(body)
    guard let constructorID = try? reader.readUInt32() else {
      log?("client: dropping unreadable message body #\(msgID)")
      return
    }

    do {
      switch constructorID {
      case MTProtoClientID.msgContainer:
        // A negative/garbage count from a buggy or hostile peer must not trap
        // `0..<count` (an uncatchable fatalError the enclosing do/catch can't
        // recover); treat it as a malformed message and drop it.
        let count = try reader.readInt32()
        // MTProto limits containers to 1024 messages. Every entry needs a
        // 16-byte header and at least one 4-byte constructor.
        guard count >= 0, count <= 1024, Int(count) <= reader.bytesRemaining / 20 else {
          throw MTProtoClientSessionError.badEnvelope
        }
        for _ in 0..<count {
          let leafMsgID = try reader.readInt64()
          let leafSeqNo = try reader.readInt32()
          let length = Int(try reader.readInt32())
          guard length >= 0 else { throw MTProtoClientSessionError.badEnvelope }
          let leafBody = try reader.readRawBytes(length)
          if let rejection = validator.validate(msgID: leafMsgID, now: crypto.adjustedNow) {
            log?("client: dropping container leaf \(leafMsgID): \(rejection)")
            continue
          }
          handleBody(
            leafBody, msgID: leafMsgID, seqNo: leafSeqNo, envelopeMsgID: envelopeMsgID,
            recordAck: true, depth: depth + 1, remainingInflatedBytes: &remainingInflatedBytes)
        }

      case MTProtoClientID.gzipPacked:
        let inflated = try MTProtoGzip.inflate(
          try reader.readBytes(), maximumOutputSize: remainingInflatedBytes)
        remainingInflatedBytes -= inflated.count
        handleBody(
          inflated, msgID: msgID, seqNo: seqNo, envelopeMsgID: envelopeMsgID,
          recordAck: false, depth: depth + 1, remainingInflatedBytes: &remainingInflatedBytes)

      case MTProtoClientID.rpcResult:
        let reqMsgID = try reader.readInt64()
        let result = try reader.readRawBytes(reader.bytesRemaining)
        handleRPCResult(
          reqMsgID: reqMsgID, result: result, remainingInflatedBytes: &remainingInflatedBytes)

      case MTProtoClientID.pong:
        _ = try reader.readInt64()  // msg_id of the ping
        let pingID = try reader.readInt64()
        if let ping = pendingPings.removeValue(forKey: pingID) {
          ping.continuation.resume()
        }

      case MTProtoClientID.badServerSalt:
        let badMsgID = try reader.readInt64()
        _ = try reader.readInt32()  // bad_msg_seqno
        _ = try reader.readInt32()  // error_code (48)
        let newSalt = try reader.readInt64()
        log?("client: bad_server_salt for #\(badMsgID); adopting new salt")
        crypto.adoptSalt(newSalt)
        saltValidUntil = 0
        resendQuery(badMsgID)

      case MTProtoClientID.badMsgNotification:
        let badMsgID = try reader.readInt64()
        _ = try reader.readInt32()  // bad_msg_seqno
        let errorCode = try reader.readInt32()
        handleBadMessage(badMsgID: badMsgID, errorCode: errorCode, envelopeMsgID: envelopeMsgID)

      case MTProtoClientID.newSessionCreated:
        let firstMsgID = try reader.readInt64()
        _ = try reader.readInt64()  // unique_id
        let serverSalt = try reader.readInt64()
        log?("client: new_session_created (salt=\(serverSalt))")
        crypto.adoptSalt(serverSalt)
        saltValidUntil = 0
        // Queries sent before the session's first server-visible message may
        // have been lost (e.g. a server restart); resend them. msg_ids are
        // ordered *unsigned* (unixtime << 32), so compare as UInt64 — a
        // signed compare would misclassify ids once the high bit sets (2038).
        let firstUnsigned = UInt64(bitPattern: firstMsgID)
        for oldMsgID in pendingKeysAscending()
        where UInt64(bitPattern: oldMsgID) < firstUnsigned {
          resendQuery(oldMsgID)
        }

      case MTProtoClientID.futureSalts:
        _ = try reader.readInt64()  // req_msg_id
        let now = try reader.readInt32()
        let count = try reader.readInt32()
        guard count >= 0 else {
          log?("client: dropping future_salts with negative count \(count)")
          return
        }
        var adopted: (salt: Int64, validUntil: Int32)?
        for _ in 0..<count {
          // Bare future_salt: valid_since:int valid_until:int salt:long.
          let validSince = try reader.readInt32()
          let validUntil = try reader.readInt32()
          let salt = try reader.readInt64()
          // Prefer the currently valid salt; fall back to the freshest.
          if validSince <= now && now < validUntil || adopted == nil {
            adopted = (salt, validUntil)
          }
        }
        if let adopted {
          crypto.adoptSalt(adopted.salt)
          saltValidUntil = Int64(adopted.validUntil)
        }

      case MTProtoClientID.msgsAck, MTProtoClientID.msgsStateInfo,
        MTProtoClientID.msgDetailedInfo, MTProtoClientID.msgNewDetailedInfo:
        break  // delivery bookkeeping; correlation runs off rpc_result alone

      default:
        // Server-initiated content (API updates, …): the caller's concern.
        if let onUnhandledMessage = configuration.onUnhandledMessage {
          onUnhandledMessage(body)
        } else {
          log?(
            "client: unhandled server message 0x\(String(constructorID, radix: 16)) #\(msgID)")
        }
      }
    } catch {
      log?("client: error handling message #\(msgID): \(error)")
    }
  }

  private func handleRPCResult(reqMsgID: Int64, result: Data, remainingInflatedBytes: inout Int) {
    guard pending[reqMsgID] != nil else {
      log?("client: rpc_result for unknown #\(reqMsgID)")
      return
    }
    var body = result
    // The result object itself may be gzip-wrapped.
    var reader = TLReader(body)
    if (try? reader.peekUInt32()) == MTProtoClientID.gzipPacked {
      _ = try? reader.readUInt32()
      guard let packed = try? reader.readBytes(),
        let inflated = try? MTProtoGzip.inflate(packed, maximumOutputSize: remainingInflatedBytes)
      else {
        log?("client: dropping undecodable gzip_packed rpc_result #\(reqMsgID)")
        return
      }
      remainingInflatedBytes -= inflated.count
      body = inflated
    }
    guard let query = pending.removeValue(forKey: reqMsgID) else {
      log?("client: rpc_result for unknown #\(reqMsgID)")
      return
    }
    var resultReader = TLReader(body)
    if (try? resultReader.peekUInt32()) == MTProtoClientID.rpcError,
      let error = try? TL.RpcError(tlFrom: &resultReader)
    {
      query.continuation.resume(
        throwing: MTProtoRPCError(code: error.errorCode, message: error.errorMessage))
    } else {
      query.continuation.resume(returning: body)
    }
  }

  private func handleBadMessage(badMsgID: Int64, errorCode: Int32, envelopeMsgID: Int64) {
    log?("client: bad_msg_notification \(errorCode) for #\(badMsgID)")
    switch errorCode {
    case 16, 20:
      // msg_id too low / stale: re-anchor our clock estimate on the server's
      // (authenticated) reply id and resend under a fresh id.
      crypto.updateTimeOffset(fromServerMsgID: envelopeMsgID)
      resendQuery(badMsgID)
    case 17:
      // msg_id too far in the future: fix the clock estimate and recreate the
      // session, resending everything in flight.
      crypto.updateTimeOffset(fromServerMsgID: envelopeMsgID)
      crypto.startNewSession()
      validator.reset()
      pendingAcks.removeAll()
      for oldMsgID in pendingKeysAscending() { resendQuery(oldMsgID) }
    default:
      // 18/19/32–35/64…: a malformed message or a broken seq_no/session — a
      // client bug, fatal for the connection (protocol §6).
      failAll(.fatalBadMessage(code: errorCode))
      closeTransport?()
    }
  }

  // MARK: - Acknowledgements

  private func scheduleAckFlush() {
    // Large backlogs flush immediately; otherwise batch for a beat so one
    // msgs_ack covers a burst of server messages. An armed timer is orphaned
    // rather than cancelled: cancelling a `Task.sleep` leaks (swiftlang/swift#60441).
    if pendingAcks.count >= 32 {
      ackFlushArmed = false
      ackFlushGeneration &+= 1
      flushAcks()
      return
    }
    guard !ackFlushArmed else { return }
    ackFlushArmed = true
    ackFlushGeneration &+= 1
    let generation = ackFlushGeneration
    Task { [weak self] in
      try? await Task.sleep(for: .milliseconds(500))
      await self?.ackFlushDue(generation)
    }
  }

  /// Flushes only for the arming that is still current; an orphan says nothing.
  private func ackFlushDue(_ generation: UInt64) {
    guard generation == ackFlushGeneration else { return }
    ackFlushArmed = false
    flushAcks()
  }

  private func flushAcks() {
    guard case .ready = phase, !pendingAcks.isEmpty else { return }
    let body = TL.MsgsAck(msgIds: pendingAcks).tlSerialized()
    pendingAcks.removeAll()
    _ = try? sendMessage(body: body, contentRelated: false)
  }

  // MARK: - Ping / salt upkeep

  private func startPingLoopIfNeeded() {
    guard !pingLoopRunning, let interval = configuration.pingInterval else { return }
    pingLoopRunning = true
    // The loop ends on the phase rather than on cancellation: cancelling a
    // `Task.sleep` leaks (swiftlang/swift#60441).
    Task { [weak self] in
      while true {
        try? await Task.sleep(for: interval)
        guard let self, await self.pingTickUnlessClosed(interval: interval) else { return }
      }
    }
  }

  /// One turn of the ping loop, answering whether it should sleep again.
  private func pingTickUnlessClosed(interval: Duration) -> Bool {
    if case .closed = phase { return false }
    pingTick(interval: interval)
    return true
  }

  private func pingTick(interval: Duration) {
    guard case .ready = phase else { return }
    let pingID = nextPingID
    nextPingID += 1
    // Ask the server to disconnect us if the *next* probe goes missing too —
    // the standard idle-liveness contract.
    let delay = Int32(min(max(interval.components.seconds * 2 + 15, 35), 3600))
    let ping = TL.PingDelayDisconnect(pingId: pingID, disconnectDelay: delay)
      .tlSerialized()
    do {
      // Piggyback any due acknowledgements in one container with the ping —
      // the batched form of the ack contract.
      if !pendingAcks.isEmpty {
        let acks = TL.MsgsAck(msgIds: pendingAcks).tlSerialized()
        pendingAcks.removeAll()
        try sendContainer([(acks, false), (ping, false)])
      } else {
        _ = try sendMessage(body: ping, contentRelated: false)
      }
    } catch {
      log?("client: ping failed to send: \(error)")
    }
    // Proactively refresh the salt when the known validity nears its end.
    let now = crypto.adjustedNow
    if saltValidUntil != 0, saltValidUntil - now < 900 {
      _ = try? sendMessage(
        body: TL.GetFutureSalts(num: 1).tlSerialized(), contentRelated: true)
    }
  }
}
