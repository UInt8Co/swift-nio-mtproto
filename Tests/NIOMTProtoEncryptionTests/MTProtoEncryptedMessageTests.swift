import MTProtoCrypto
import NIOMTProtoEncryption
import TLCoding
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// The MTProto 2.0 encrypted envelope codec, exercised in both directions
/// with a fixed (random) auth key.
@Suite struct MTProtoEncryptedMessageTests {
  let authKey = randomData(256)
  var authKeyID: Int64 { MTProtoMessageCrypto.authKeyID(authKey) }

  func roundTrip(
    bodyLength: Int, direction: MTProtoMessageCrypto.Direction,
    sourceLocation: SourceLocation = #_sourceLocation
  ) throws {
    let body = randomData(bodyLength)
    let payload = try MTProtoEncryptedMessage.encode(
      body: body, salt: 0x1111_2222_3333_4444, sessionID: 42, msgID: 1_234_567,
      seqNo: 7, authKey: authKey, authKeyID: authKeyID, direction: direction)

    // Envelope shape: auth_key_id ‖ msg_key ‖ ciphertext (16-byte blocks).
    #expect((payload.count - 24) % 16 == 0, sourceLocation: sourceLocation)
    var reader = TLReader(payload)
    #expect(try reader.readInt64() == authKeyID, sourceLocation: sourceLocation)

    // Padding: 12–1024 bytes, total plaintext a multiple of 16.
    let plaintextLength = payload.count - 24
    let padding = plaintextLength - 32 - body.count
    #expect(padding >= 12, sourceLocation: sourceLocation)
    #expect(padding <= 1024, sourceLocation: sourceLocation)

    let message = try MTProtoEncryptedMessage.decode(
      payload, authKey: authKey, direction: direction)
    #expect(message.salt == 0x1111_2222_3333_4444, sourceLocation: sourceLocation)
    #expect(message.sessionID == 42, sourceLocation: sourceLocation)
    #expect(message.msgID == 1_234_567, sourceLocation: sourceLocation)
    #expect(message.seqNo == 7, sourceLocation: sourceLocation)
    #expect(message.body == body, sourceLocation: sourceLocation)
  }

  @Test func roundTripFromClient() throws {
    for length in [0, 1, 4, 15, 16, 100, 1000] {
      try roundTrip(bodyLength: length, direction: .fromClient)
    }
  }

  @Test func roundTripFromServer() throws {
    for length in [0, 4, 64] {
      try roundTrip(bodyLength: length, direction: .fromServer)
    }
  }

  @Test func directionsUseDistinctKeys() throws {
    // A client→server envelope must not authenticate as server→client.
    let payload = try MTProtoEncryptedMessage.encode(
      body: randomData(32), salt: 1, sessionID: 2, msgID: 3, seqNo: 0,
      authKey: authKey, authKeyID: authKeyID, direction: .fromClient)
    #expect(throws: MTProtoEncryptedMessage.DecodeError.msgKeyMismatch) {
      try MTProtoEncryptedMessage.decode(payload, authKey: authKey, direction: .fromServer)
    }
  }

  @Test func tamperedMsgKeyIsRejected() throws {
    var payload = try MTProtoEncryptedMessage.encode(
      body: randomData(32), salt: 1, sessionID: 2, msgID: 3, seqNo: 0,
      authKey: authKey, authKeyID: authKeyID, direction: .fromClient)
    payload[payload.startIndex + 10] ^= 0xFF  // inside msg_key
    #expect(throws: MTProtoEncryptedMessage.DecodeError.msgKeyMismatch) {
      try MTProtoEncryptedMessage.decode(payload, authKey: authKey)
    }
  }

  @Test func tamperedCiphertextIsRejected() throws {
    var payload = try MTProtoEncryptedMessage.encode(
      body: randomData(32), salt: 1, sessionID: 2, msgID: 3, seqNo: 0,
      authKey: authKey, authKeyID: authKeyID, direction: .fromClient)
    payload[payload.endIndex - 1] ^= 0xFF
    #expect(throws: MTProtoEncryptedMessage.DecodeError.msgKeyMismatch) {
      try MTProtoEncryptedMessage.decode(payload, authKey: authKey)
    }
  }

  @Test func wrongAuthKeyIsRejected() throws {
    let payload = try MTProtoEncryptedMessage.encode(
      body: randomData(32), salt: 1, sessionID: 2, msgID: 3, seqNo: 0,
      authKey: authKey, authKeyID: authKeyID, direction: .fromClient)
    #expect(throws: MTProtoEncryptedMessage.DecodeError.msgKeyMismatch) {
      try MTProtoEncryptedMessage.decode(payload, authKey: randomData(256))
    }
  }

  @Test func tooShortPayloads() {
    for length in [0, 8, 23, 24, 24 + 8] {  // 24+8: ciphertext not block-aligned
      #expect(throws: MTProtoEncryptedMessage.DecodeError.tooShort) {
        try MTProtoEncryptedMessage.decode(randomData(length), authKey: authKey)
      }
    }
  }

  @Test func badInnerLengthIsRejected() throws {
    // Hand-roll an envelope whose inner `length` field exceeds the plaintext.
    var inner = TLWriter()
    inner.writeInt64(0)  // salt
    inner.writeInt64(0)  // session_id
    inner.writeInt64(0)  // msg_id
    inner.writeInt32(0)  // seq_no
    inner.writeInt32(9999)  // length (bogus)
    inner.writeRawData(randomData(16))  // padding to 48 bytes
    #expect(throws: MTProtoEncryptedMessage.DecodeError.badInnerLength(9999)) {
      try decodeHandRolled(inner.data)
    }
  }

  @Test func tooSmallPaddingIsRejected() throws {
    // A well-authenticated plaintext that leaves 0 bytes of padding violates
    // the MTProto 2.0 12–1024-byte requirement.
    var inner = TLWriter()
    inner.writeInt64(0)  // salt
    inner.writeInt64(0)  // session_id
    inner.writeInt64(0)  // msg_id
    inner.writeInt32(0)  // seq_no
    inner.writeInt32(16)  // length
    inner.writeRawData(randomData(16))  // body, no trailing padding → 48 bytes
    #expect(throws: MTProtoEncryptedMessage.DecodeError.badPadding(0)) {
      try decodeHandRolled(inner.data)
    }
  }

  /// Seals a hand-rolled plaintext into a valid envelope (correct `msg_key`)
  /// so `decode`'s post-authentication checks can be exercised.
  private func decodeHandRolled(_ plaintext: Data) throws -> MTProtoPlainMessage {
    #expect(plaintext.count % 16 == 0)
    let msgKey = MTProtoMessageCrypto.messageKey(
      authKey: authKey, plaintext: plaintext, direction: .fromClient)
    let (key, iv) = MTProtoMessageCrypto.aesKeyIV(
      authKey: authKey, msgKey: msgKey, direction: .fromClient)
    var writer = TLWriter()
    writer.writeInt64(authKeyID)
    writer.writeRawData(msgKey)
    writer.writeRawData(try AESIGE.encrypt(plaintext, key: key, iv: iv))
    return try MTProtoEncryptedMessage.decode(writer.data, authKey: authKey)
  }
}
