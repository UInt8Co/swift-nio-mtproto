import NIOMTProtoEncryption
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Tests for ``InMemoryAuthKeyStore``'s LRU eviction: the store caps its
/// session count and evicts the least-recently-used entry when the cap is
/// exceeded.
@Suite struct InMemoryAuthKeyStoreTests {
  private static let dummy = MTProtoStoredSession(
    authKey: Data(repeating: 0xAB, count: 256), serverSalt: 42)

  @Test("stores and retrieves a session")
  func storeAndRetrieve() async {
    let store = InMemoryAuthKeyStore()
    await store.store(Self.dummy, id: 1)
    let got = await store.session(for: 1)
    #expect(got == Self.dummy)
  }

  @Test("returns nil for unknown id")
  func unknownID() async {
    let store = InMemoryAuthKeyStore()
    #expect(await store.session(for: 99) == nil)
  }

  @Test("count stays at or below maxCount under many inserts")
  func boundedGrowth() async {
    let store = InMemoryAuthKeyStore(maxCount: 10)
    for id in Int64(1)...100 { await store.store(Self.dummy, id: id) }
    #expect(await store.sessionCount <= 10)
  }

  @Test("evicts the least-recently-used session when over cap")
  func evictsLRU() async {
    let store = InMemoryAuthKeyStore(maxCount: 3)

    // Fill to capacity: ids 1, 2, 3 (in that access order).
    await store.store(Self.dummy, id: 1)
    await store.store(Self.dummy, id: 2)
    await store.store(Self.dummy, id: 3)
    #expect(await store.sessionCount == 3)

    // Promote id=1 so it is the most recently used.
    _ = await store.session(for: 1)

    // Inserting id=4 must evict the LRU entry (id=2).
    await store.store(Self.dummy, id: 4)
    #expect(await store.sessionCount == 3)
    #expect(await store.session(for: 2) == nil, "LRU entry evicted")
    #expect(await store.session(for: 1) != nil, "recently accessed entry survives")
    #expect(await store.session(for: 3) != nil, "second-oldest entry survives")
    #expect(await store.session(for: 4) != nil, "newly inserted entry survives")
  }

  @Test("re-storing an existing id refreshes its recency")
  func reStoreRefreshesRecency() async {
    let store = InMemoryAuthKeyStore(maxCount: 2)

    await store.store(Self.dummy, id: 1)
    await store.store(Self.dummy, id: 2)

    // Re-store id=1 — it becomes the most recent; id=2 becomes the LRU.
    await store.store(Self.dummy, id: 1)

    // Inserting id=3 must evict id=2 (now LRU), not id=1.
    await store.store(Self.dummy, id: 3)
    #expect(await store.sessionCount == 2)
    #expect(await store.session(for: 2) == nil, "stale entry evicted")
    #expect(await store.session(for: 1) != nil, "re-stored entry survives")
    #expect(await store.session(for: 3) != nil, "newest entry survives")
  }

  @Test("maxCount 0 disables eviction")
  func noEvictionWhenUnlimited() async {
    let store = InMemoryAuthKeyStore(maxCount: 0)
    for id in Int64(1)...50 { await store.store(Self.dummy, id: id) }
    #expect(await store.sessionCount == 50)
  }
}
