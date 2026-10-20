import MTProtoBaseSchema
import MTProtoClientKit
import MTProtoCrypto
import NIOMTProtoEncryption
import TLCoding
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

@Suite struct ClientPingRecoveryTests {
  @Test(arguments: [Int32(16), 17, 20, 32, 33])
  func pingSurvivesSaltThenBadMessage(code: Int32) async throws {
    var peer = try await PingPeer.make()
    let connection = peer.connection
    let ping = Task { try await connection.ping() }
    let original = try await peer.next()
    let token = try TL.Ping(tlData: original.body).pingId
    try await peer.send(
      TL.BadServerSalt(
        badMsgId: original.msgID, badMsgSeqno: original.seqNo,
        errorCode: 48, newServerSalt: 123
      ).tlSerialized(), to: original)
    let salted = try await peer.next()
    #expect(salted.msgID != original.msgID)
    #expect(salted.salt == 123)
    #expect(try TL.Ping(tlData: salted.body).pingId == token)
    // Replaying a correction for the replaced message must not resend it again.
    try await peer.send(
      TL.BadServerSalt(
        badMsgId: original.msgID, badMsgSeqno: original.seqNo,
        errorCode: 48, newServerSalt: 123
      ).tlSerialized(), to: salted)
    try await peer.send(
      TL.BadMsgNotification(
        badMsgId: salted.msgID, badMsgSeqno: salted.seqNo, errorCode: code
      ).tlSerialized(),
      to: salted, timeOffset: code == 17 ? -10 : 10)
    let corrected = try await peer.next()
    #expect(corrected.msgID != salted.msgID)
    #expect(corrected.salt == 123)
    let correctedTime = Int64(UInt64(bitPattern: corrected.msgID) >> 32)
    let expectedTime = Int64(Date().timeIntervalSince1970) + (code == 17 ? -10 : 10)
    #expect(abs(correctedTime - expectedTime) <= 1)
    #expect(corrected.seqNo % 2 == 0)
    #expect(try TL.Ping(tlData: corrected.body).pingId == token)
    if [17, 32, 33].contains(code) {
      #expect(corrected.sessionID != salted.sessionID)
    }
    let pong = TL.Pong(msgId: corrected.msgID, pingId: token).tlSerialized()
    try await peer.send(pong, to: corrected)
    try await ping.value
    try await peer.send(pong, to: corrected)
    await peer.connection.channelInactive()
  }

  @Test(arguments: [Int32(16), 17, 20, 32, 33])
  func badMessageWithoutSaltCorrectionUsesFreshMessageID(code: Int32) async throws {
    var peer = try await PingPeer.make()
    let connection = peer.connection
    let ping = Task { try await connection.ping() }
    let request = try await peer.next()
    let token = try TL.Ping(tlData: request.body).pingId
    try await peer.send(
      TL.BadMsgNotification(
        badMsgId: request.msgID, badMsgSeqno: request.seqNo, errorCode: code
      ).tlSerialized(),
      to: request)
    let resent = try await peer.next()
    #expect(resent.msgID != request.msgID)
    #expect(try TL.Ping(tlData: resent.body).pingId == token)
    try await peer.send(TL.Pong(msgId: resent.msgID, pingId: token).tlSerialized(), to: resent)
    try await ping.value
    await connection.channelInactive()
  }

  @Test func sessionResetResendsEveryWaiterWithoutOverwritingQueries() async throws {
    var peer = try await PingPeer.make()
    let connection = peer.connection
    let first = Task { try await connection.invoke(Data([1, 0, 0, 0])) }
    _ = try await peer.next()
    let second = Task { try await connection.invoke(Data([2, 0, 0, 0])) }
    _ = try await peer.next()
    let ping = Task { try await connection.ping() }
    let request = try await peer.next()
    let token = try TL.Ping(tlData: request.body).pingId
    try await peer.send(
      TL.BadMsgNotification(
        badMsgId: request.msgID, badMsgSeqno: request.seqNo, errorCode: 17
      ).tlSerialized(),
      to: request)
    for _ in 0..<3 {
      let resent = try await peer.next()
      #expect(resent.sessionID != request.sessionID)
      if let value = try? TL.Ping(tlData: resent.body) {
        #expect(value.pingId == token)
        try await peer.send(TL.Pong(msgId: resent.msgID, pingId: token).tlSerialized(), to: resent)
      } else {
        var response = TLWriter()
        response.writeUInt32(TL.RpcResult.tlConstructorID)
        response.writeInt64(resent.msgID)
        response.writeRawData(resent.body)
        try await peer.send(response.data, to: resent)
      }
    }
    #expect(try await first.value == Data([1, 0, 0, 0]))
    #expect(try await second.value == Data([2, 0, 0, 0]))
    try await ping.value
    await connection.channelInactive()
  }

  @Test func newSessionRecoversEarlierPing() async throws {
    var peer = try await PingPeer.make()
    let connection = peer.connection
    let ping = Task { try await connection.ping() }
    let request = try await peer.next()
    let token = try TL.Ping(tlData: request.body).pingId
    try await peer.send(
      TL.NewSessionCreated(firstMsgId: request.msgID + 4, uniqueId: 1, serverSalt: 456)
        .tlSerialized(), to: request)
    let resent = try await peer.next()
    #expect(resent.salt == 456)
    #expect(try TL.Ping(tlData: resent.body).pingId == token)
    try await peer.send(TL.Pong(msgId: resent.msgID, pingId: token).tlSerialized(), to: resent)
    try await ping.value
    await connection.channelInactive()
  }

  @Test func missingPongTimesOutOnceAtOriginalDeadline() async throws {
    var peer = try await PingPeer.make(timeout: .milliseconds(500))
    let connection = peer.connection
    let ping = Task { try await connection.ping() }
    let request = try await peer.next()
    // Measure from the actual send, excluding time the task spent waiting for
    // an executor while other suites run their synchronous crypto fixtures.
    let started = ContinuousClock.now
    let token = try TL.Ping(tlData: request.body).pingId
    try await Task.sleep(for: .milliseconds(350))
    try await peer.send(
      TL.BadServerSalt(
        badMsgId: request.msgID, badMsgSeqno: request.seqNo,
        errorCode: 48, newServerSalt: 789
      ).tlSerialized(), to: request)
    let resent = try await peer.next()
    // An unrelated keepalive pong must not complete the explicit ping.
    try await peer.send(TL.Pong(msgId: resent.msgID, pingId: token + 1).tlSerialized(), to: resent)
    await #expect(throws: MTProtoClientError.timeout) { try await ping.value }
    #expect(started.duration(to: .now) < .milliseconds(750))
    // Both completion paths must find the waiter gone after the timeout.
    try await peer.send(TL.Pong(msgId: resent.msgID, pingId: token).tlSerialized(), to: resent)
    await connection.channelInactive()
  }

  @Test func disconnectCompletesResentPingOnce() async throws {
    var peer = try await PingPeer.make(timeout: .milliseconds(250))
    let connection = peer.connection
    let ping = Task { try await connection.ping() }
    let request = try await peer.next()
    try await peer.send(
      TL.BadServerSalt(
        badMsgId: request.msgID, badMsgSeqno: request.seqNo,
        errorCode: 48, newServerSalt: 1
      ).tlSerialized(), to: request)
    _ = try await peer.next()
    await connection.channelInactive()
    await #expect(throws: MTProtoClientError.connectionClosed) { try await ping.value }
    try await Task.sleep(for: .milliseconds(300))
  }
}

/// Exchanges encrypted transport payloads with the actual session actor.
private struct PingPeer {
  let connection: MTProtoClientConnection
  let authKey: Data
  var writes: AsyncStream<Data>.Iterator
  var serverSequence: Int64 = 0

  static func make(timeout: Duration = .seconds(3)) async throws -> Self {
    let authKey = randomData(256)
    let connection = MTProtoClientConnection(
      configuration: .init(
        rsaPublicKey: RSAPublicKey(testRSAKey),
        resumeSession: .init(authKey: authKey, serverSalt: 0),
        pingInterval: nil, requestTimeout: timeout))
    let (writes, sink) = AsyncStream<Data>.makeStream()
    await connection.channelActive(write: { sink.yield($0) }, close: { sink.finish() })
    // Bound a failed test's read too, without cancelling a sleeping task.
    Task {
      try? await Task.sleep(for: .seconds(5))
      sink.finish()
    }
    return Self(connection: connection, authKey: authKey, writes: writes.makeAsyncIterator())
  }

  mutating func next() async throws -> MTProtoPlainMessage {
    let payload = try #require(await writes.next())
    return try MTProtoEncryptedMessage.decode(payload, authKey: authKey, direction: .fromClient)
  }

  mutating func send(
    _ body: Data, to request: MTProtoPlainMessage, timeOffset: Int64 = 0
  ) async throws {
    let msgID = ((Int64(Date().timeIntervalSince1970) + timeOffset) << 32) + serverSequence * 4 + 1
    serverSequence += 1
    let payload = try MTProtoEncryptedMessage.encode(
      body: body, salt: request.salt, sessionID: request.sessionID, msgID: msgID, seqNo: 0,
      authKey: authKey, authKeyID: MTProtoMessageCrypto.authKeyID(authKey), direction: .fromServer)
    await connection.handleInbound(payload)
  }
}
