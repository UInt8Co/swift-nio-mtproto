import MTProtoUtils
import NIOCore
import NIOEmbedded
import Testing

@testable import NIOMTProtoTransport

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

// MARK: - Helpers

private func hex(_ string: String) -> [UInt8] {
  var bytes = [UInt8]()
  var iter = string.makeIterator()
  while let hi = iter.next(), let lo = iter.next() {
    bytes.append(UInt8(String([hi, lo]), radix: 16)!)
  }
  return bytes
}

private func buffer(_ bytes: [UInt8]) -> ByteBuffer {
  var b = ByteBufferAllocator().buffer(capacity: bytes.count)
  b.writeBytes(bytes)
  return b
}

private func bytes(of buffer: ByteBuffer) -> [UInt8] {
  buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
}

/// Frames `payload` with an encoder, returning the raw wire bytes.
private func encode(_ payload: [UInt8], _ transport: MTProtoTransport) throws -> [UInt8] {
  let channel = EmbeddedChannel(handler: MTProtoFrameEncoder(transport: transport))
  try channel.writeOutbound(buffer(payload))
  let out = try #require(try channel.readOutbound(as: ByteBuffer.self))
  _ = try channel.finish()
  return bytes(of: out)
}

/// Decodes a single payload from `wire` with a decoder.
private func decode(_ wire: [UInt8], _ transport: MTProtoTransport) throws -> [UInt8]? {
  let channel = EmbeddedChannel(
    handler: ByteToMessageHandler(MTProtoFrameDecoder(transport: transport)))
  try channel.writeInbound(buffer(wire))
  let out = try channel.readInbound(as: ByteBuffer.self)
  _ = try channel.finish()
  return out.map(bytes(of:))
}

// MARK: - Framing: exact bytes

@Test func abridgedShortFraming() throws {
  let payload = hex("01000000")  // one 4-byte word
  #expect(try encode(payload, .abridged) == hex("01") + payload)
}

@Test func abridgedLongFraming() throws {
  // 127 words (508 bytes) forces the long form: 0x7f + 3-byte LE word count.
  let payload = [UInt8](repeating: 0xAB, count: 508)
  let wire = try encode(payload, .abridged)
  #expect(Array(wire[0..<4]) == hex("7f7f0000"))  // 0x7f marker, words = 0x00007f
  #expect(Array(wire[4...]) == payload)
}

@Test func intermediateFraming() throws {
  let payload = hex("deadbeef")
  #expect(try encode(payload, .intermediate) == hex("04000000") + payload)
}

@Test func paddedIntermediateLengthCoversPadding() throws {
  let payload = [UInt8](repeating: 0x11, count: 8)
  let wire = try encode(payload, .paddedIntermediate)
  let declared = Int(wire[0]) | Int(wire[1]) << 8 | Int(wire[2]) << 16 | Int(wire[3]) << 24
  #expect(declared == wire.count - 4)  // length includes the random padding
  #expect(declared >= payload.count && declared <= payload.count + 15)
  #expect(Array(wire[4..<(4 + payload.count)]) == payload)
}

@Test func fullFramingHasSeqnoAndCRC() throws {
  let payload = hex("deadbeef")
  let wire = try encode(payload, .full)
  // length(4) seqno(4) payload(4) crc(4) = 16 bytes, seqno starts at 0.
  #expect(wire.count == 16)
  #expect(Array(wire[0..<4]) == hex("10000000"))
  #expect(Array(wire[4..<8]) == hex("00000000"))
  #expect(Array(wire[8..<12]) == payload)
  let expectedCRC = CRC32.checksum(of: wire[0..<12])
  let crc =
    UInt32(wire[12]) | UInt32(wire[13]) << 8 | UInt32(wire[14]) << 16 | UInt32(wire[15])
    << 24
  #expect(crc == expectedCRC)
}

@Test func fullSeqnoIncrements() throws {
  let channel = EmbeddedChannel(handler: MTProtoFrameEncoder(transport: .full))
  try channel.writeOutbound(buffer(hex("aaaaaaaa")))
  try channel.writeOutbound(buffer(hex("bbbbbbbb")))
  _ = try channel.readOutbound(as: ByteBuffer.self)
  let second = bytes(of: try #require(try channel.readOutbound(as: ByteBuffer.self)))
  #expect(Array(second[4..<8]) == hex("01000000"))  // seqno == 1
  _ = try channel.finish()
}

// MARK: - Framing: round trips

@Test(arguments: [
  MTProtoTransport.abridged, .intermediate, .paddedIntermediate, .full,
])
func roundTrip(_ transport: MTProtoTransport) throws {
  for wordCount in [1, 2, 16, 200] {
    let payload = (0..<(wordCount * 4)).map { UInt8($0 & 0xff) }
    let wire = try encode(payload, transport)
    let decoded = try #require(try decode(wire, transport))
    if transport == .paddedIntermediate {
      // The decoder cannot know the padding length, so it emits payload +
      // 0...15 trailing bytes; the upper layer strips them.
      #expect(Array(decoded.prefix(payload.count)) == payload)
      #expect((payload.count...payload.count + 15).contains(decoded.count))
    } else {
      #expect(decoded == payload, "round trip failed for \(transport) @ \(payload.count) bytes")
    }
  }
}

@Test func decoderWaitsForFullFrame() throws {
  let channel = EmbeddedChannel(
    handler: ByteToMessageHandler(MTProtoFrameDecoder(transport: .intermediate)))
  // 8 bytes: a realistic minimum MTProto payload (avoids the 4-byte error-code
  // heuristic, which a real message never triggers).
  let payload = hex("0102030405060708")
  let wire = try encode(payload, .intermediate)
  // Feed the frame one byte at a time; nothing should decode until complete.
  for i in 0..<(wire.count - 1) {
    try channel.writeInbound(buffer([wire[i]]))
    #expect(try channel.readInbound(as: ByteBuffer.self) == nil)
  }
  try channel.writeInbound(buffer([wire[wire.count - 1]]))
  #expect(try channel.readInbound(as: ByteBuffer.self).map(bytes(of:)) == payload)
  _ = try channel.finish()
}

// MARK: - Transport-level errors

@Test func decodesNegativeErrorCode() throws {
  // -404 little-endian, framed as a 4-byte intermediate packet.
  let code = Int32(-404)
  let body = withUnsafeBytes(of: code.littleEndian) { Array($0) }
  let wire = try encode(body, .intermediate)
  #expect {
    _ = try decode(wire, .intermediate)
  } throws: { error in
    error as? MTProtoTransportError == .serverError(code: 404)
  }
}

@Test func detectsCRCMismatch() throws {
  var wire = try encode(hex("deadbeef"), .full)
  wire[12] ^= 0xff  // corrupt the CRC
  #expect(throws: MTProtoTransportError.self) {
    _ = try decode(wire, .full)
  }
}

// MARK: - AES-256-CTR streaming (NIST SP 800-38A F.5.5)

private let nistKey = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
private let nistIV = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
private let nistPlain = hex(
  "6bc1bee22e409f96e93d7e117393172a"
    + "ae2d8a571e03ac9c9eb76fac45af8e51"
    + "30c81c46a35ce411e5fbc1191a0a52ef"
    + "f69f2445df4f9b17ad2b417be66c3710")
private let nistCipher = hex(
  "601ec313775789a5b7a7f504bbf3d228"
    + "f443e3ca4d62b59aca84e990cacaf5c5"
    + "2b0930daa23de94ce87017ba2d84988d"
    + "dfc9c58db67aada613c2dd08457941a6")

@Test func aesCTRMatchesNISTVectorWholeBlock() {
  var stream = AESCTRStream(key: Data(nistKey), iv: Data(nistIV))
  #expect(stream.apply(nistPlain) == nistCipher)
}

@Test func aesCTRMatchesNISTVectorChunked() {
  // Feed in deliberately unaligned chunks to exercise counter advance and the
  // leftover-keystream buffer.
  var stream = AESCTRStream(key: Data(nistKey), iv: Data(nistIV))
  var out = [UInt8]()
  var index = 0
  for size in [1, 7, 8, 16, 5, 27] {  // sums to 64
    out += stream.apply(Array(nistPlain[index..<index + size]))
    index += size
  }
  #expect(out == nistCipher)
}

@Test func aesCTRIsItsOwnInverse() {
  var enc = AESCTRStream(key: Data(nistKey), iv: Data(nistIV))
  var dec = AESCTRStream(key: Data(nistKey), iv: Data(nistIV))
  let message = (0..<100).map { UInt8($0) }
  #expect(dec.apply(enc.apply(message)) == message)
}

// MARK: - Obfuscation handshake

/// A deterministic 64-byte init payload that satisfies the preamble rules.
private let fixedPayload: [UInt8] = (0..<64).map { UInt8(($0 * 7 + 1) & 0xff) }

@Test func handshakeHeaderLayout() throws {
  let handshake = try MTProtoObfuscation.makeHandshake(
    transport: .abridged, secret: nil, dcId: nil, initPayload: fixedPayload)
  #expect(handshake.header.count == 64)
  // First 56 bytes are the plaintext payload verbatim.
  #expect(Array(handshake.header[0..<56]) == Array(fixedPayload[0..<56]))
}

@Test func handshakeRejectsFullTransport() {
  #expect(throws: MTProtoTransportError.self) {
    _ = try MTProtoObfuscation.makeHandshake(
      transport: .full, secret: nil, dcId: nil, initPayload: fixedPayload)
  }
}

@Test func randomPayloadSatisfiesPreambleRules() {
  var rng = SystemRandomNumberGenerator()
  for _ in 0..<1000 {
    let payload = MTProtoObfuscation.makeRandomPayload(using: &rng)
    #expect(MTProtoObfuscation.isValidPreamble(payload))
  }
}

@Test func preambleRulesRejectKnownMagics() {
  // 0xef first byte, the intermediate/padded magics, and a zero second word.
  #expect(!MTProtoObfuscation.isValidPreamble([0xef] + [UInt8](repeating: 1, count: 63)))
  #expect(
    !MTProtoObfuscation.isValidPreamble(
      hex("eeeeeeee") + [UInt8](repeating: 1, count: 60)))
  #expect(
    !MTProtoObfuscation.isValidPreamble(
      hex("01020304") + hex("00000000") + [UInt8](repeating: 1, count: 56)))
}

// MARK: - Obfuscation handler (end to end through an EmbeddedChannel)

@Test func obfuscationHandlerEncryptsOutbound() throws {
  let channel = EmbeddedChannel()
  let handler = MTProtoObfuscationHandler(
    transport: .abridged, secret: nil, dcId: nil, fixedInitPayload: fixedPayload)
  try channel.pipeline.syncOperations.addHandler(handler)
  try channel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 80)).wait()

  // First outbound bytes are the 64-byte obfuscation header.
  let header = bytes(of: try #require(try channel.readOutbound(as: ByteBuffer.self)))
  #expect(header.count == 64)

  // Reproduce the expected keystream independently from the same payload.
  let handshake = try MTProtoObfuscation.makeHandshake(
    transport: .abridged, secret: nil, dcId: nil, initPayload: fixedPayload)
  #expect(header == handshake.header)

  let plaintext = (0..<32).map { UInt8($0) }
  try channel.writeOutbound(buffer(plaintext))
  let encrypted = bytes(of: try #require(try channel.readOutbound(as: ByteBuffer.self)))

  var expectedCipher = handshake.encrypt  // already advanced past the header
  #expect(encrypted == expectedCipher.apply(plaintext))
  _ = try? channel.finish()
}

@Test func obfuscationHandlerDecryptsInbound() throws {
  let channel = EmbeddedChannel()
  let handler = MTProtoObfuscationHandler(
    transport: .abridged, secret: nil, dcId: nil, fixedInitPayload: fixedPayload)
  try channel.pipeline.syncOperations.addHandler(handler)
  try channel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 80)).wait()
  _ = try channel.readOutbound(as: ByteBuffer.self)  // discard header

  // Derive the decryption key/IV the handler will use (from the reversed
  // payload) and pre-encrypt a server message with it.
  let reversed = Array(fixedPayload.reversed())
  var serverSide = AESCTRStream(key: Data(reversed[8..<40]), iv: Data(reversed[40..<56]))
  let serverPlaintext = (100..<150).map { UInt8($0 & 0xff) }
  let ciphertext = serverSide.apply(serverPlaintext)

  try channel.writeInbound(buffer(ciphertext))
  let decrypted = bytes(of: try #require(try channel.readInbound(as: ByteBuffer.self)))
  #expect(decrypted == serverPlaintext)
  _ = try? channel.finish()
}

// MARK: - Pipeline configuration

@Test func pipelineConfigRejectsObfuscatedFull() {
  let config = MTProtoTransportConfiguration(transport: .full, obfuscation: .init())
  #expect(throws: MTProtoTransportError.self) {
    _ = try config.makeHandlers()
  }
}

@Test func pipelineConfigBuildsThreeHandlers() throws {
  let config = MTProtoTransportConfiguration(transport: .intermediate)
  #expect(try config.makeHandlers().count == 3)
}
