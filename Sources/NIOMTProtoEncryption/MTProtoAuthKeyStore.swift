#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// One persisted MTProto session: the negotiated auth key and the server salt
/// that was in force when it was negotiated.
///
/// Persisting the salt (not just the key) lets a reconnecting peer keep using
/// the salt it remembers from the original handshake instead of paying a
/// `bad_server_salt` round-trip on every reconnect.
public struct MTProtoStoredSession: Sendable, Equatable {
  /// The 256-byte shared auth key.
  public var authKey: Data
  /// The server salt issued for the session (`new_nonce[0..8] XOR
  /// server_nonce[0..8]` at handshake time).
  public var serverSalt: Int64
  /// For a PFS *temporary* key, the unix timestamp at which it expires
  /// (`server_time + expires_in`); `0` for an ordinary permanent key. An
  /// expired temporary key is treated as unknown, forcing the client to
  /// generate and bind a fresh one.
  public var expiresAt: Int32

  public init(authKey: Data, serverSalt: Int64, expiresAt: Int32 = 0) {
    self.authKey = authKey
    self.serverSalt = serverSalt
    self.expiresAt = expiresAt
  }
}

/// A recorded `temp_auth_key_id → perm_auth_key_id` binding (the product of a
/// successful `auth.bindTempAuthKey`). Messages encrypted with the temporary
/// key act under the permanent key's identity, so the permanent key is what
/// account state (authorizations, access hashes) attaches to.
public struct MTProtoTempKeyBinding: Sendable, Equatable {
  /// The permanent key the temporary key is bound to.
  public var permAuthKeyID: Int64
  /// The temporary key's expiry (unix timestamp), copied from the binding so a
  /// reconnecting client's bound key can be expiry-checked without the
  /// session row.
  public var expiresAt: Int32

  public init(permAuthKeyID: Int64, expiresAt: Int32) {
    self.permAuthKeyID = permAuthKeyID
    self.expiresAt = expiresAt
  }
}

/// Persistence for negotiated sessions, keyed by `auth_key_id`, so a
/// reconnection can reuse a key from a previous handshake instead of repeating
/// the DH exchange.
///
/// Implementations may be backed by anything from an in-memory dictionary
/// (``InMemoryAuthKeyStore``) to a database; every method is `async` so a
/// production store can do I/O.
public protocol MTProtoAuthKeyStore: Sendable {
  /// Persists a freshly negotiated session (auth key + server salt) under its
  /// `auth_key_id`.
  func store(_ session: MTProtoStoredSession, id: Int64) async
  /// Looks up the session for `id`, or nil if unknown.
  func session(for id: Int64) async -> MTProtoStoredSession?
  /// Records a `temp_auth_key_id → perm_auth_key_id` PFS binding. Replaces any
  /// previous binding for the same temporary key.
  func bindTempKey(tempAuthKeyID: Int64, permAuthKeyID: Int64, expiresAt: Int32) async
  /// The permanent key (and expiry) a temporary key is bound to, or nil if the
  /// temporary key was never bound.
  ///
  /// Declared as a requirement (not given a default) so an `actor` conformer's
  /// synchronous witness is reached through dynamic dispatch — a default
  /// implementation would statically shadow it and silently no-op.
  func tempKeyBinding(for tempAuthKeyID: Int64) async -> MTProtoTempKeyBinding?
}

/// The trivial in-memory ``MTProtoAuthKeyStore``: sessions live for the
/// lifetime of the process, subject to an LRU cap.
///
/// `maxCount` bounds how many sessions are kept. When a new session would
/// exceed the cap, the least-recently-used entry is evicted first. Set it to 0
/// to disable eviction (tests only).
public actor InMemoryAuthKeyStore: MTProtoAuthKeyStore {
  private struct Entry {
    var session: MTProtoStoredSession
    /// Monotonically increasing access counter — higher = more recent.
    var order: Int
  }
  private var entries: [Int64: Entry] = [:]
  private var bindings: [Int64: MTProtoTempKeyBinding] = [:]
  private var clock: Int = 0
  private let maxCount: Int

  public init(maxCount: Int = 10_000) {
    self.maxCount = maxCount
  }

  public func store(_ session: MTProtoStoredSession, id: Int64) {
    clock += 1
    entries[id] = Entry(session: session, order: clock)
    evictIfNeeded()
  }

  public func session(for id: Int64) -> MTProtoStoredSession? {
    guard entries[id] != nil else { return nil }
    clock += 1
    entries[id]?.order = clock
    return entries[id]?.session
  }

  public func bindTempKey(tempAuthKeyID: Int64, permAuthKeyID: Int64, expiresAt: Int32) {
    bindings[tempAuthKeyID] = MTProtoTempKeyBinding(
      permAuthKeyID: permAuthKeyID, expiresAt: expiresAt)
  }

  public func tempKeyBinding(for tempAuthKeyID: Int64) -> MTProtoTempKeyBinding? {
    bindings[tempAuthKeyID]
  }

  /// Number of cached sessions; useful for diagnostics and tests.
  public var sessionCount: Int { entries.count }

  private func evictIfNeeded() {
    guard maxCount > 0, entries.count > maxCount else { return }
    let overage = entries.count - maxCount
    let toEvict = entries.sorted { $0.value.order < $1.value.order }.prefix(overage)
    for (key, _) in toEvict { entries.removeValue(forKey: key) }
  }
}
