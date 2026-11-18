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

  /// The envelope byte for byte, against one assembled here from the message
  /// layer's primitives with the padding pinned.
  @Test func envelopeBytesAreExact() throws {
    for direction in [MTProtoMessageCrypto.Direction.fromClient, .fromServer] {
      for length in [0, 1, 4, 11, 12, 15, 16, 17, 100, 1000, 70_000] {
        let body = randomData(length)
        var padLength = 16 - ((32 + length) % 16)
        if padLength < 12 { padLength += 16 }
        let padding = randomData(padLength)

        var inner = TLWriter()
        inner.writeInt64(-2)  // salt
        inner.writeInt64(0x0102_0304_0506_0708)  // session_id
        inner.writeInt64(Int64.max)  // msg_id
        inner.writeInt32(-5)  // seq_no
        inner.writeInt32(Int32(length))
        inner.writeRawData(body)
        inner.writeRawData(padding)
        let msgKey = MTProtoMessageCrypto.messageKey(
          authKey: authKey, plaintext: inner.data, direction: direction)
        let (key, iv) = MTProtoMessageCrypto.aesKeyIV(
          authKey: authKey, msgKey: msgKey, direction: direction)
        var expected = TLWriter()
        expected.writeInt64(authKeyID)
        expected.writeRawData(msgKey)
        expected.writeRawData(try AESIGE.encrypt(inner.data, key: key, iv: iv))

        var requested: [Int] = []
        let payload = try MTProtoEncryptedMessage.encode(
          body: body, salt: -2, sessionID: 0x0102_0304_0506_0708, msgID: Int64.max, seqNo: -5,
          authKey: authKey, authKeyID: authKeyID, direction: direction,
          randomPadding: {
            requested.append($0)
            return padding
          })
        #expect(requested == [padLength])
        #expect(payload == expected.data, "\(length)-byte body")
        #expect(payload.startIndex == 0)

        let message = try MTProtoEncryptedMessage.decode(
          expected.data, authKey: authKey, direction: direction)
        #expect(
          message
            == MTProtoPlainMessage(
              salt: -2, sessionID: 0x0102_0304_0506_0708, msgID: Int64.max, seqNo: -5,
              body: body))
        #expect(message.body.startIndex == 0)
      }
    }
  }

  /// The body and the envelope may be slices of larger buffers, as they are
  /// when cut out of a container or a transport frame.
  @Test func slicedInputsAreReadFromWhereTheyStart() throws {
    let body = randomData(40)
    let wholeBody = randomData(7) + body + randomData(5)
    let padding = randomData(24)
    let reference = try MTProtoEncryptedMessage.encode(
      body: body, salt: 1, sessionID: 2, msgID: 3, seqNo: 4, authKey: authKey,
      authKeyID: authKeyID, direction: .fromClient, randomPadding: { _ in padding })
    let fromSlice = try MTProtoEncryptedMessage.encode(
      body: wholeBody[7..<47], salt: 1, sessionID: 2, msgID: 3, seqNo: 4, authKey: authKey,
      authKeyID: authKeyID, direction: .fromClient,
      randomPadding: { _ in (randomData(3) + padding)[3...] })
    #expect(fromSlice == reference)

    let framed = randomData(9) + reference + randomData(4)
    let message = try MTProtoEncryptedMessage.decode(
      framed[9..<(9 + reference.count)], authKey: authKey)
    #expect(message.body == body)
    #expect(message.body.startIndex == 0)

    // A slice is held to the same shape and authenticity checks.
    #expect(throws: MTProtoEncryptedMessage.DecodeError.tooShort) {
      try MTProtoEncryptedMessage.decode(framed[9..<(9 + 24 + 8)], authKey: authKey)
    }
    #expect(throws: MTProtoEncryptedMessage.DecodeError.msgKeyMismatch) {
      try MTProtoEncryptedMessage.decode(framed[8..<(8 + reference.count)], authKey: authKey)
    }
  }

  @Test func paddingThatBreaksBlockAlignmentIsRejected() {
    #expect(throws: MTProtoCryptoError.invalidBlockAlignment(length: 32 + 32 + 5)) {
      try MTProtoEncryptedMessage.encode(
        body: randomData(32), salt: 1, sessionID: 2, msgID: 3, seqNo: 0,
        authKey: authKey, authKeyID: authKeyID, randomPadding: { _ in randomData(5) })
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
