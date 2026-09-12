import MTProtoBaseSchema
import MTProtoClientKit
import MTProtoCrypto
import NIOMTProtoEncryption
import Synchronization
import TLCoding
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

@Suite struct ClientMessageSecurityTests {
  @Test func boundsNestedContainerProcessing() async throws {
    let peer = try await Peer.make()
    var body = Data([0x11, 0x22, 0x33, 0x44])
    for sequence in 0..<40 {
      var writer = TLWriter()
      writer.writeUInt32(0x73f1_f8dc)
      writer.writeInt32(1)
      writer.writeInt64(peer.id(sequence))
      writer.writeInt32(0)
      writer.writeInt32(Int32(body.count))
      writer.writeRawData(body)
      body = writer.data
    }
    try await peer.send(body, sequence: 40)
    #expect(peer.observed.delivered.withLock { $0.isEmpty })
    #expect(peer.observed.logs.withLock { $0.contains { $0.contains("excessively nested") } })
    // Dropping a malformed message must leave the session usable.
    let ordinary = Data([0x11, 0x22, 0x33, 0x44])
    try await peer.send(ordinary, sequence: 41)
    #expect(peer.observed.delivered.withLock { $0 == [ordinary] })
    await peer.finish()
  }

  @Test func acceptsOrdinaryContainer() async throws {
    let peer = try await Peer.make()
    let leaf = Data([0x11, 0x22, 0x33, 0x44])
    var writer = TLWriter()
    writer.writeUInt32(0x73f1_f8dc)
    writer.writeInt32(2)
    for sequence in 0..<2 {
      writer.writeInt64(peer.id(sequence))
      writer.writeInt32(0)
      writer.writeInt32(4)
      writer.writeRawData(leaf)
    }
    try await peer.send(writer.data, sequence: 2)
    #expect(peer.observed.delivered.withLock { $0 == [leaf, leaf] })
    await peer.finish()
  }

  @Test func limitsCombinedExpansionAcrossContainerSiblings() async throws {
    let peer = try await Peer.make()
    // Each fixed gzip member expands to 32768 bytes. Repeating it 513 times
    // fits in a small frame but crosses the shared 16 MiB inflation budget.
    let compressed = try #require(
      Data(
        base64Encoded:
          "H4sIAAAAAAAAA+3BgQAAAACAILb9pRapCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY3t4zZwCAAAA="
      ))
    var packed = TLWriter()
    packed.writeUInt32(0x3072_cfa1)
    packed.writeBytes(compressed)
    var container = TLWriter()
    container.writeUInt32(0x73f1_f8dc)
    container.writeInt32(513)
    for sequence in 0..<513 {
      container.writeInt64(peer.id(sequence))
      container.writeInt32(0)
      container.writeInt32(Int32(packed.data.count))
      container.writeRawData(packed.data)
    }
    try await peer.send(container.data, sequence: 513)
    #expect(peer.observed.delivered.withLock { $0.count == 512 })
    #expect(peer.observed.logs.withLock { $0.contains { $0.contains("outputLimitExceeded") } })
    await peer.finish()
  }
}

private struct Peer {
  final class Observed: Sendable {
    let delivered = Mutex<[Data]>([])
    let logs = Mutex<[String]>([])
  }

  let connection: MTProtoClientConnection
  let request: Task<Void, Error>
  let authKey: Data
  let sessionID: Int64
  let now: Int64
  let observed: Observed

  static func make() async throws -> Peer {
    let authKey = randomData(256)
    let observed = Observed()
    let connection = MTProtoClientConnection(
      configuration: .init(
        rsaPublicKey: RSAPublicKey(testRSAKey),
        resumeSession: .init(authKey: authKey, serverSalt: 0),
        pingInterval: nil, requestTimeout: .seconds(5),
        onUnhandledMessage: { body in observed.delivered.withLock { $0.append(body) } },
        log: { line in observed.logs.withLock { $0.append(line) } }))
    let (writes, sink) = AsyncStream<Data>.makeStream()
    await connection.channelActive(write: { sink.yield($0) }, close: {})
    let request = Task { try await connection.ping() }
    var iterator = writes.makeAsyncIterator()
    let outbound = try #require(await iterator.next())
    let message = try MTProtoEncryptedMessage.decode(
      outbound, authKey: authKey, direction: .fromClient)
    return Peer(
      connection: connection, request: request, authKey: authKey,
      sessionID: message.sessionID, now: Int64(Date().timeIntervalSince1970),
      observed: observed)
  }

  func id(_ sequence: Int) -> Int64 { (now << 32) + Int64(sequence) * 4 + 1 }

  func send(_ body: Data, sequence: Int) async throws {
    let payload = try MTProtoEncryptedMessage.encode(
      body: body, salt: 0, sessionID: sessionID, msgID: id(sequence), seqNo: 0,
      authKey: authKey, authKeyID: MTProtoMessageCrypto.authKeyID(authKey), direction: .fromServer)
    await connection.handleInbound(payload)
  }

  func finish() async {
    await connection.channelInactive()
    _ = await request.result
  }
}
