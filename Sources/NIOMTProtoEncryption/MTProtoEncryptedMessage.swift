import MTProtoCrypto
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// One decrypted MTProto message, as carried inside the encrypted envelope:
/// `salt`, `session_id`, `msg_id`, `seq_no`, and the message body.
public struct MTProtoPlainMessage: Equatable, Sendable {
  public var salt: Int64
  public var sessionID: Int64
  public var msgID: Int64
  public var seqNo: Int32
  /// The serialized message body (a boxed TL object: an RPC query, a container,
  /// or a service message).
  public var body: Data

  public init(salt: Int64, sessionID: Int64, msgID: Int64, seqNo: Int32, body: Data) {
    self.salt = salt
    self.sessionID = sessionID
    self.msgID = msgID
    self.seqNo = seqNo
    self.body = body
  }
}

/// Encodes and decodes the MTProto 2.0 *encrypted* message envelope
/// (<https://core.telegram.org/mtproto/description#encrypted-message>):
///
/// ```
/// auth_key_id : long
/// msg_key     : int128            (middle 128 bits of SHA256(key_part ‖ plaintext))
/// encrypted_data : AES-256-IGE( salt ‖ session_id ‖ msg_id ‖ seq_no ‖ length ‖ body ‖ padding )
/// ```
public enum MTProtoEncryptedMessage {
  public enum DecodeError: Error, Equatable {
    case tooShort
    case unknownAuthKey(Int64)
    case msgKeyMismatch
    case badInnerLength(Int)
    /// The trailing padding wasn't within the MTProto 2.0 range of 12–1024
    /// bytes (a sign of a malformed or tampered message).
    case badPadding(Int)
  }

  /// Decrypts and parses one direction of the encrypted envelope. A client
  /// decodes what it receives with `direction: .fromServer`; the accepting end
  /// of a connection decodes with `.fromClient`.
  public static func decode(
    _ data: Data, authKey: Data,
    direction: MTProtoMessageCrypto.Direction = .fromClient
  ) throws -> MTProtoPlainMessage {
    guard data.count >= 24, (data.count - 24) % 16 == 0, data.count > 24 else {
      throw DecodeError.tooShort
    }
    let bytes = [UInt8](data)
    let msgKey = Data(bytes[8..<24])
    let encrypted = Data(bytes[24...])

    let (key, iv) = MTProtoMessageCrypto.aesKeyIV(
      authKey: authKey, msgKey: msgKey, direction: direction)
    let plaintext = try AESIGE.decrypt(encrypted, key: key, iv: iv)

    // Verify msg_key = middle128(SHA256(authKey[88..120] ‖ plaintext)). The
    // comparison is constant-time: msg_key authenticates the message, so its
    // verification must not leak where it first differs.
    let expectedMsgKey = MTProtoMessageCrypto.messageKey(
      authKey: authKey, plaintext: plaintext, direction: direction)
    guard MTProtoConstantTime.equals(expectedMsgKey, msgKey) else {
      throw DecodeError.msgKeyMismatch
    }

    var reader = TLReader(plaintext)
    let salt = try reader.readInt64()
    let sessionID = try reader.readInt64()
    let msgID = try reader.readInt64()
    let seqNo = try reader.readInt32()
    let length = Int(try reader.readInt32())
    guard length >= 0, length <= reader.bytesRemaining else {
      throw DecodeError.badInnerLength(length)
    }
    let body = try reader.readRawBytes(length)
    // MTProto 2.0 requires 12–1024 bytes of trailing random padding; whatever
    // is left after the body is that padding.
    let padding = reader.bytesRemaining
    guard padding >= 12, padding <= 1024 else { throw DecodeError.badPadding(padding) }
    return MTProtoPlainMessage(
      salt: salt, sessionID: sessionID, msgID: msgID, seqNo: seqNo, body: body)
  }

  /// Builds one direction of the encrypted envelope from a body and the
  /// session's salt / session id / msg id / seq no. A client encodes with
  /// `direction: .fromClient`; the accepting end with `.fromServer`.
  public static func encode(
    body: Data, salt: Int64, sessionID: Int64, msgID: Int64, seqNo: Int32,
    authKey: Data, authKeyID: Int64,
    direction: MTProtoMessageCrypto.Direction = .fromServer,
    randomPadding: (Int) -> Data = randomData
  ) throws -> Data {
    var inner = TLWriter()
    inner.writeInt64(salt)
    inner.writeInt64(sessionID)
    inner.writeInt64(msgID)
    inner.writeInt32(seqNo)
    inner.writeInt32(Int32(body.count))
    inner.writeRawData(body)
    // MTProto 2.0 padding: 12–1024 bytes, total length a multiple of 16.
    let unpadded = inner.data.count
    var padLength = 16 - (unpadded % 16)
    if padLength < 12 { padLength += 16 }
    inner.writeRawData(randomPadding(padLength))

    let plaintext = inner.data
    let msgKey = MTProtoMessageCrypto.messageKey(
      authKey: authKey, plaintext: plaintext, direction: direction)
    let (key, iv) = MTProtoMessageCrypto.aesKeyIV(
      authKey: authKey, msgKey: msgKey, direction: direction)
    let encrypted = try AESIGE.encrypt(plaintext, key: key, iv: iv)

    var out = TLWriter()
    out.writeInt64(authKeyID)
    out.writeRawData(msgKey)
    out.writeRawData(encrypted)
    return out.data
  }
}

/// Cryptographically random bytes; a free function so it can be used as the
/// default `randomPadding` and from non-isolated contexts.
public func randomData(_ count: Int) -> Data {
  var rng = SystemRandomNumberGenerator()
  var bytes = [UInt8](repeating: 0, count: count)
  for i in 0..<count { bytes[i] = rng.next() }
  return Data(bytes)
}
