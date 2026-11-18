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

// Byte-exact expectations for everything this module puts on the wire or takes
// off it. The literals were produced once and are not derived from the code
// under test, so a change to how the bytes are assembled, buffered or
// enciphered cannot move them unnoticed.

// MARK: - Helpers

private func hex(_ string: String) -> [UInt8] {
  var bytes = [UInt8]()
  var iter = string.makeIterator()
  while let hi = iter.next(), let lo = iter.next() {
    bytes.append(UInt8(String([hi, lo]), radix: 16)!)
  }
  return bytes
}

private func buffer(_ bytes: some Collection<UInt8>) -> ByteBuffer {
  var b = ByteBufferAllocator().buffer(capacity: bytes.count)
  b.writeBytes(bytes)
  return b
}

private func bytes(of buffer: ByteBuffer) -> [UInt8] {
  buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) ?? []
}

private func littleEndian(_ value: UInt32) -> [UInt8] {
  (0..<4).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
}

private func pattern(_ count: Int, seed: Int) -> [UInt8] {
  (0..<count).map { UInt8(truncatingIfNeeded: $0 &* 13 &+ seed) }
}

/// One frame built by hand, independently of ``MTProtoFrameEncoder``.
/// `padding` only applies to the padded intermediate transport.
private func frame(
  _ payload: [UInt8], _ transport: MTProtoTransport, sequence: UInt32 = 0,
  padding: [UInt8] = []
) -> [UInt8] {
  switch transport {
  case .abridged:
    let words = payload.count / 4
    if words < 0x7f { return [UInt8(words)] + payload }
    return [0x7f] + littleEndian(UInt32(words)).prefix(3) + payload
  case .intermediate:
    return littleEndian(UInt32(payload.count)) + payload
  case .paddedIntermediate:
    return littleEndian(UInt32(payload.count + padding.count)) + payload + padding
  case .full:
    let head = littleEndian(UInt32(payload.count + 12)) + littleEndian(sequence) + payload
    return head + littleEndian(CRC32.checksum(of: head))
  }
}

/// A wire stream of several frames and the payloads a decoder must emit for it.
private struct Stream {
  var wire: [UInt8] = []
  var payloads: [[UInt8]] = []

  init(_ transport: MTProtoTransport, payloadSizes: [Int]) {
    for (index, size) in payloadSizes.enumerated() {
      let payload = pattern(size, seed: index &* 31 &+ 7)
      // The decoder cannot tell the padding from the payload, so it emits both.
      let padding = transport == .paddedIntermediate ? pattern(index % 16, seed: 0xe0) : []
      wire += frame(payload, transport, sequence: UInt32(index), padding: padding)
      payloads.append(payload + padding)
    }
  }
}

/// Feeds `chunks` to `handlers` and returns every payload that came out.
private func decode(
  _ chunks: [ArraySlice<UInt8>], through handlers: [any ChannelHandler]
) throws -> [[UInt8]] {
  let channel = EmbeddedChannel(handlers: handlers)
  var out: [[UInt8]] = []
  for chunk in chunks {
    try channel.writeInbound(buffer(chunk))
    while let payload = try channel.readInbound(as: ByteBuffer.self) {
      out.append(bytes(of: payload))
    }
  }
  _ = try channel.finish()
  return out
}

private func chunks(_ wire: [UInt8], of size: Int) -> [ArraySlice<UInt8>] {
  stride(from: 0, to: wire.count, by: size).map { wire[$0..<min($0 + size, wire.count)] }
}

private func decoder(_ transport: MTProtoTransport) -> any ChannelHandler {
  ByteToMessageHandler(MTProtoFrameDecoder(transport: transport))
}

/// Writes each payload to `handlers` and returns the buffers that reached the
/// socket end, one entry per buffer.
private func write(
  _ payloads: [[UInt8]], through handlers: [any ChannelHandler]
) throws -> [[UInt8]] {
  let channel = EmbeddedChannel(handlers: handlers)
  var out: [[UInt8]] = []
  for payload in payloads {
    try channel.writeOutbound(buffer(payload))
    while let wire = try channel.readOutbound(as: ByteBuffer.self) {
      out.append(bytes(of: wire))
    }
  }
  _ = try channel.finish()
  return out
}

// MARK: - Framing: exact outbound bytes

@Test func goldenAbridgedFrames() throws {
  let short = hex("0102030405060708")
  let long = pattern(508, seed: 1)  // 127 words: the first length needing the long form
  let longer = pattern(1024, seed: 2)  // 256 words: a carry into the second length byte
  let wire = try write(
    [short, long, longer], through: [MTProtoFrameEncoder(transport: .abridged)])
  #expect(wire == [hex("02") + short, hex("7f7f0000") + long, hex("7f000100") + longer])
}

@Test func goldenIntermediateFrames() throws {
  let short = hex("0102030405060708")
  let long = pattern(70_000, seed: 3)
  let wire = try write([short, long], through: [MTProtoFrameEncoder(transport: .intermediate)])
  #expect(wire == [hex("08000000") + short, hex("70110100") + long])
}

@Test func goldenFullFrames() throws {
  let wire = try write(
    [hex("deadbeef"), hex("0102030405060708")],
    through: [MTProtoFrameEncoder(transport: .full)])
  #expect(
    wire == [
      hex("1000000000000000deadbeefd557152a"),
      hex("140000000100000001020304050607088f22e01f"),
    ])
}

@Test func paddedIntermediateFramesKeepThePayloadAndCountThePadding() throws {
  // Odd lengths are legal here, and 200 frames see every padding length.
  let payloads = (0..<200).map { pattern(5 + $0, seed: $0) }
  let wire = try write(payloads, through: [MTProtoFrameEncoder(transport: .paddedIntermediate)])
  #expect(wire.count == payloads.count)
  var paddings = Set<Int>()
  for (frame, payload) in zip(wire, payloads) {
    let declared = Int(frame[0]) | Int(frame[1]) << 8 | Int(frame[2]) << 16 | Int(frame[3]) << 24
    #expect(declared == frame.count - 4)
    #expect(Array(frame[4..<4 + payload.count]) == payload)
    paddings.insert(declared - payload.count)
  }
  #expect(paddings.isSubset(of: Set(0...15)))
  #expect(paddings.count > 8)
}

/// A handler below the encoder may send each buffer as a message of its own —
/// a WebSocket frame, say — and peers read one MTProto packet per message, so a
/// frame must reach it whole.
@Test(arguments: MTProtoTransport.allCases)
func everyFrameIsOneOutboundBuffer(_ transport: MTProtoTransport) throws {
  let payloads = [8, 508, 70_000].map { pattern($0, seed: $0) }
  let wire = try write(payloads, through: [MTProtoFrameEncoder(transport: transport)])
  #expect(wire.count == payloads.count)
}

/// The payload handed to the encoder still belongs to whoever wrote it.
@Test(arguments: MTProtoTransport.allCases)
func encodingLeavesTheCallersPayloadAlone(_ transport: MTProtoTransport) throws {
  let payload = pattern(64, seed: 9)
  let kept = buffer(payload)
  let channel = EmbeddedChannel(handler: MTProtoFrameEncoder(transport: transport))
  try channel.writeOutbound(kept)
  _ = try channel.readOutbound(as: ByteBuffer.self)
  #expect(bytes(of: kept) == payload)
  _ = try channel.finish()
}

// MARK: - Framing: inbound streams however they are split

private let smallSizes = [8, 12, 16, 4 * 127, 20]
private let largeSizes = [8, 70_000, 12, 4 * 300, 8]

@Test(arguments: MTProtoTransport.allCases)
func decodesSeveralFramesFromOneRead(_ transport: MTProtoTransport) throws {
  for sizes in [smallSizes, largeSizes] {
    let stream = Stream(transport, payloadSizes: sizes)
    #expect(try decode([stream.wire[...]], through: [decoder(transport)]) == stream.payloads)
  }
}

@Test(arguments: MTProtoTransport.allCases)
func decodesAStreamSplitAtEveryByteBoundary(_ transport: MTProtoTransport) throws {
  let stream = Stream(transport, payloadSizes: [8, 12, 16, 8])
  for split in 0...stream.wire.count {
    let parts = [stream.wire[..<split], stream.wire[split...]]
    #expect(
      try decode(parts, through: [decoder(transport)]) == stream.payloads, "split at \(split)")
  }
}

@Test(arguments: MTProtoTransport.allCases)
func decodesAStreamArrivingInSmallPieces(_ transport: MTProtoTransport) throws {
  let small = Stream(transport, payloadSizes: smallSizes)
  for size in [1, 2, 3, 5, 7] {
    #expect(
      try decode(chunks(small.wire, of: size), through: [decoder(transport)]) == small.payloads,
      "\(size)-byte reads")
  }
  // A frame much larger than any single read or initial buffer.
  let large = Stream(transport, payloadSizes: largeSizes)
  for size in [1021, 4096] {
    #expect(
      try decode(chunks(large.wire, of: size), through: [decoder(transport)]) == large.payloads,
      "\(size)-byte reads")
  }
}

// MARK: - Framing: malformed input

@Test func quickAckBitIsNotPartOfTheLength() throws {
  let payload = hex("0102030405060708")
  #expect(try decode([(hex("82") + payload)[...]], through: [decoder(.abridged)]) == [payload])
  #expect(
    try decode([(hex("ff020000") + payload)[...]], through: [decoder(.abridged)]) == [payload])
  #expect(
    try decode([(hex("08000080") + payload)[...]], through: [decoder(.intermediate)])
      == [payload])
}

@Test func rejectsFramesLongerThanTheLimit() {
  func decodeLimited(_ wire: [UInt8], _ transport: MTProtoTransport) throws -> [[UInt8]] {
    try decode(
      [wire[...]],
      through: [
        ByteToMessageHandler(MTProtoFrameDecoder(transport: transport, maximumFrameLength: 1024))
      ])
  }
  // The length alone is enough: no payload has to arrive first.
  #expect(throws: MTProtoTransportError.invalidFrameLength(1028)) {
    try decodeLimited(hex("7f010100"), .abridged)
  }
  #expect(throws: MTProtoTransportError.invalidFrameLength(1028)) {
    try decodeLimited(hex("04040000"), .intermediate)
  }
  #expect(throws: MTProtoTransportError.invalidFrameLength(1028)) {
    try decodeLimited(hex("04040000"), .paddedIntermediate)
  }
  #expect(throws: MTProtoTransportError.invalidFrameLength(1028)) {
    try decodeLimited(hex("04040000"), .full)
  }
}

@Test func fullTransportReportsTheChecksumsThatDisagree() {
  var wire = hex("1000000000000000deadbeefd557152a")
  wire[9] ^= 0x01  // one payload bit
  #expect(throws: MTProtoTransportError.crcMismatch(expected: 0x2bd7_3de2, found: 0x2a15_57d5)) {
    try decode([wire[...]], through: [decoder(.full)])
  }
}

@Test func fullTransportRejectsAnOutOfOrderFrame() {
  // A well-formed frame numbered 1 where 0 is expected.
  let wire = frame(hex("0102030405060708"), .full, sequence: 1)
  #expect(throws: MTProtoTransportError.sequenceMismatch(expected: 0, found: 1)) {
    try decode([wire[...]], through: [decoder(.full)])
  }
}

@Test(arguments: MTProtoTransport.allCases)
func framesBeforeAMalformedOneAreStillDelivered(_ transport: MTProtoTransport) throws {
  let good = hex("0102030405060708")
  let bad: [UInt8] = transport == .abridged ? [0] : [0, 0, 0, 0]
  let channel = EmbeddedChannel(handler: decoder(transport))
  #expect(throws: MTProtoTransportError.self) {
    try channel.writeInbound(buffer(frame(good, transport) + bad))
  }
  #expect(try channel.readInbound(as: ByteBuffer.self).map(bytes(of:)) == good)
  #expect(try channel.readInbound(as: ByteBuffer.self) == nil)
  _ = try? channel.finish()
}

// MARK: - AES-256-CTR keystream

private let key = hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")

@Test(arguments: [
  // The counter is one 128-bit big-endian number: a carry runs its whole width,
  (
    "ffffffffffffffffffffffffffffffff",
    "3b3c2921c85a24de9ac606ce6d1d60cce568f68194cf76d6174d4cc04310a854"
      + "91151e5d0b7a1f1bc0d7acd0ae3e51e4"
  ),
  // out of the low 32 bits,
  (
    "000102030405060708090a0bffffffff",
    "b042ea9662f5c34ae9298c1a41f8d212b35381a71ab78dd7fdd85f3091d3d6bb"
      + "9dbffda6bd4d146960723f6b932aef37"
  ),
  // and out of the low 64.
  (
    "00000000000000ffffffffffffffffff",
    "0d829d4421235ef5f9ad3755c8a54d8e0ace370f7b14652a7f2e9be6fd64d6df"
      + "74312f0fb7ecfa5a86a6f903bb5f8bbe"
  ),
])
func keystreamCounterCarries(_ iv: String, _ keystream: String) {
  var stream = AESCTRStream(key: Data(key), iv: Data(hex(iv)))
  #expect(stream.apply([UInt8](repeating: 0, count: 48)) == hex(keystream))
  // The same bytes whether or not a call ends on the block that carries.
  var pieces = AESCTRStream(key: Data(key), iv: Data(hex(iv)))
  var out: [UInt8] = []
  for size in [5, 11, 1, 20, 11] { out += pieces.apply([UInt8](repeating: 0, count: size)) }
  #expect(out == hex(keystream))
}

private let longPlain = pattern(100_003, seed: 5)

@Test func keystreamOverALongInput() {
  var stream = AESCTRStream(key: Data(key), iv: Data(hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")))
  let out = stream.apply(longPlain)
  #expect(out.count == longPlain.count)
  #expect(CRC32.checksum(of: out) == 0xa62d_4cc1)
  #expect(Array(out[..<16]) == hex("0ecd62dd6051455333e00c8169ce7eca"))
  #expect(Array(out[(out.count - 19)...]) == hex("1e801f1f3550b2dc832b4d7b900b1c17c2996c"))
}

@Test func keystreamContinuesAcrossCallsOfAnySize() {
  let iv = Data(hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
  var whole = AESCTRStream(key: Data(key), iv: iv)
  let expected = whole.apply(longPlain)

  // Every way of cutting the first 100 bytes in two.
  for split in 0...100 {
    var stream = AESCTRStream(key: Data(key), iv: iv)
    let out = stream.apply(Array(longPlain[..<split])) + stream.apply(Array(longPlain[split..<100]))
    #expect(out == Array(expected[..<100]), "split at \(split)")
  }
  // Calls that end before, on and after block boundaries, all the way through.
  for size in [1, 3, 15, 16, 17, 31, 33, 4096, 4099] {
    var stream = AESCTRStream(key: Data(key), iv: iv)
    var out: [UInt8] = []
    out.reserveCapacity(longPlain.count)
    for chunk in chunks(longPlain, of: size) { out += stream.apply(Array(chunk)) }
    #expect(out == expected, "\(size)-byte calls")
  }
}

@Test func keystreamIgnoresEmptyInputAndCopiesItsState() {
  let iv = Data(hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
  var reference = AESCTRStream(key: Data(key), iv: iv)
  let expected = reference.apply(Array(longPlain[..<64]))

  var stream = AESCTRStream(key: Data(key), iv: iv)
  #expect(stream.apply([]) == [])
  let head = stream.apply(Array(longPlain[..<21]))
  #expect(stream.apply([]) == [])
  // A copy taken mid-block continues from the same place, independently.
  var copy = stream
  #expect(head + stream.apply(Array(longPlain[21..<64])) == expected)
  #expect(head + copy.apply(Array(longPlain[21..<64])) == expected)
}

/// The span forms are the array form without the arrays: the same bytes, the
/// same state afterwards, and they can be mixed call by call.
@Test func keystreamSpanFormsMatchTheArrayForm() {
  let iv = Data(hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
  var whole = AESCTRStream(key: Data(key), iv: iv)
  let expected = whole.apply(longPlain)

  for size in [1, 5, 16, 17, 100, 4099] {
    var stream = AESCTRStream(key: Data(key), iv: iv)
    var out: [UInt8] = []
    out.reserveCapacity(longPlain.count)
    for (index, chunk) in chunks(longPlain, of: size).enumerated() {
      var piece = Array(chunk)
      switch index % 3 {
      case 0:
        piece = stream.apply(piece)
      case 1:
        var typed = piece.mutableSpan
        var span = typed.mutableBytes
        stream.apply(inPlace: &span)
      default:
        // Into storage longer than the input: only the input's length is written.
        var target = [UInt8](repeating: 0xa5, count: piece.count + 3)
        do {
          var typed = target.mutableSpan
          var span = typed.mutableBytes
          stream.apply(piece.span.bytes, into: &span)
        }
        #expect(target[piece.count...].allSatisfy { $0 == 0xa5 })
        piece = Array(target[..<piece.count])
      }
      out += piece
    }
    #expect(out == expected, "\(size)-byte calls")
  }
}

// MARK: - Obfuscation: exact bytes in both directions

/// A deterministic 64-byte init payload that satisfies the preamble rules.
private let initPayload: [UInt8] = (0..<64).map { UInt8(($0 * 7 + 1) & 0xff) }
private let plain: [UInt8] = (0..<100).map { UInt8($0) }

/// What an initiator with `initPayload` puts on the wire and expects back:
/// the 64-byte header, then `plain` as it leaves (`outbound`), and the bytes
/// that arrive carrying `plain` from the accepting end (`inbound`).
private struct ObfuscationVector: Sendable, CustomTestStringConvertible {
  var testDescription: String
  var transport: MTProtoTransport
  var secret: Data?
  var dcId: Int16?
  var header: [UInt8]
  var outbound: [UInt8]
  var inbound: [UInt8]

  /// Without a secret the keys come from the init payload alone, so the
  /// streams are the same for every transport; only the header's tag differs.
  static let plainOutbound = hex(
    "e3c1d05626c5a2af082958146d9f31682b28a11c3df31de4d51bd5fc716aefaf"
      + "1106ea64db95225ca268706a95db8e57879ed1a7d1f23ca5be915b815e17b7c2"
      + "a9106016734f2c400093b1f4138cbfd0e30328654e51860ea437e5ab4067afcf"
      + "560684ad")
  static let plainInbound = hex(
    "a153cf8c8dcfbf4d02ce10ce479db4d88e121ab24702cf3622fd122bf96a30b8"
      + "58e255410793ab51c0fccf735689698d81c3616abc07ef36222efde75e1fa5e1"
      + "799f6336f50d8794a73017f1980d4e8b8f540ef4477baf88c523794a88b144c3"
      + "59141ba5")
  static let headerPrefix =
    "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da"
    + "e1e8eff6fd040b121920272e353c434a51585f666d747b82"

  static let all: [ObfuscationVector] = [
    ObfuscationVector(
      testDescription: "abridged", transport: .abridged,
      header: hex(headerPrefix + "5f32568e7501f691"),
      outbound: plainOutbound, inbound: plainInbound),
    ObfuscationVector(
      testDescription: "intermediate", transport: .intermediate,
      header: hex(headerPrefix + "5e33578f7501f691"),
      outbound: plainOutbound, inbound: plainInbound),
    ObfuscationVector(
      testDescription: "padded intermediate", transport: .paddedIntermediate,
      header: hex(headerPrefix + "6d0064bc7501f691"),
      outbound: plainOutbound, inbound: plainInbound),
    ObfuscationVector(
      testDescription: "intermediate through a proxy", transport: .intermediate,
      secret: Data((0..<16).map { UInt8(0xa0 + $0) }), dcId: -3,
      header: hex(headerPrefix + "be4693561c35ac56"),
      outbound: hex(
        "eb8cb93ad610ad7411f9394277c9871fc041a5f2f20e0753567ef4102c4a525a"
          + "7a0c6bf55110b4450e37e5638b3b2cb283926027743649017477a1d39196de4f"
          + "fcc0f1270c0dfc074cd5edf2cfef730e2a2dd51236cf15132a41cb6502ecd22c"
          + "225f8e71"),
      inbound: hex(
        "cdadbf221de819bb3bb1d5630846978223b30b1e16248ac606ddfa608757deef"
          + "bb6bc7ea24adfe7eccecd01e9f661db36613b3e6e8ec10f80aa8664a7566f1d1"
          + "9cb80264613152c1a9044fd8631fd36d2f9ba72a71a076be93382c9ad8dbac3f"
          + "ee62000b")),
  ]

  /// A connected channel holding only the initiating handler, its header
  /// already taken off the outbound side.
  func initiator() throws -> (channel: EmbeddedChannel, header: [UInt8]) {
    let channel = EmbeddedChannel()
    try channel.pipeline.syncOperations.addHandler(
      MTProtoObfuscationHandler(
        transport: transport, secret: secret, dcId: dcId, fixedInitPayload: initPayload))
    try channel.connect(to: SocketAddress(ipAddress: "1.2.3.4", port: 80)).wait()
    let header = bytes(of: try #require(try channel.readOutbound(as: ByteBuffer.self)))
    return (channel, header)
  }

  /// The handler for the end that received `header`.
  func acceptor() throws -> MTProtoObfuscationHandler {
    let accepted = try MTProtoObfuscation.acceptHandshake(received: header, secret: secret)
    return MTProtoObfuscationHandler(
      encrypt: accepted.encrypt, decrypt: accepted.decrypt, transport: accepted.transport)
  }
}

@Test(arguments: ObfuscationVector.all)
private func goldenObfuscationHandshake(_ vector: ObfuscationVector) throws {
  var handshake = try MTProtoObfuscation.makeHandshake(
    transport: vector.transport, secret: vector.secret, dcId: vector.dcId,
    initPayload: initPayload)
  #expect(handshake.header == vector.header)
  #expect(handshake.encrypt.apply(plain) == vector.outbound)
  #expect(handshake.decrypt.apply(vector.inbound) == plain)

  var accepted = try MTProtoObfuscation.acceptHandshake(
    received: vector.header, secret: vector.secret)
  #expect(accepted.transport == vector.transport)
  #expect(accepted.decrypt.apply(vector.outbound) == plain)
  #expect(accepted.encrypt.apply(plain) == vector.inbound)
}

@Test(arguments: ObfuscationVector.all)
private func goldenObfuscatedWrites(_ vector: ObfuscationVector) throws {
  // However the plaintext is cut into writes, the same bytes leave, one
  // buffer per write.
  for split in 0...plain.count {
    let (channel, header) = try vector.initiator()
    #expect(header == vector.header)
    var out: [[UInt8]] = []
    for part in [plain[..<split], plain[split...]] where !part.isEmpty {
      try channel.writeOutbound(buffer(part))
      out.append(bytes(of: try #require(try channel.readOutbound(as: ByteBuffer.self))))
      #expect(try channel.readOutbound(as: ByteBuffer.self) == nil)
    }
    #expect(out.map(\.count) == [split, plain.count - split].filter { $0 > 0 })
    #expect(Array(out.joined()) == vector.outbound, "split at \(split)")
    _ = try? channel.finish()
  }

  // The accepting end's writes are the initiator's inbound bytes.
  for split in 0...plain.count {
    let wire = try write(
      [Array(plain[..<split]), Array(plain[split...])].filter { !$0.isEmpty },
      through: [vector.acceptor()])
    #expect(Array(wire.joined()) == vector.inbound, "split at \(split)")
  }
}

@Test(arguments: ObfuscationVector.all)
private func goldenObfuscatedReads(_ vector: ObfuscationVector) throws {
  for split in 0...plain.count {
    let (channel, _) = try vector.initiator()
    var out: [UInt8] = []
    for part in [vector.inbound[..<split], vector.inbound[split...]] where !part.isEmpty {
      try channel.writeInbound(buffer(part))
      out += bytes(of: try #require(try channel.readInbound(as: ByteBuffer.self)))
    }
    #expect(out == plain, "split at \(split)")
    _ = try? channel.finish()

    let parts = [vector.outbound[..<split], vector.outbound[split...]].filter { !$0.isEmpty }
    let read = try decode(parts, through: [vector.acceptor()])
    #expect(Array(read.joined()) == plain, "split at \(split)")
  }
}

/// A buffer that reaches the handler is still someone else's: the bytes a
/// caller wrote, or read, are not enciphered under it.
@Test func obfuscationLeavesTheCallersBuffersAlone() throws {
  let vector = ObfuscationVector.all[0]
  let (channel, _) = try vector.initiator()
  let outbound = buffer(plain)
  try channel.writeOutbound(outbound)
  #expect(bytes(of: outbound) == plain)
  let inbound = buffer(vector.inbound)
  try channel.writeInbound(inbound)
  #expect(bytes(of: inbound) == vector.inbound)
  _ = try? channel.finish()
}

@Test func emptyBuffersPassThroughObfuscationWithoutMovingTheKeystream() throws {
  let vector = ObfuscationVector.all[0]
  let (channel, _) = try vector.initiator()
  try channel.writeOutbound(buffer([]))
  #expect(try channel.readOutbound(as: ByteBuffer.self)?.readableBytes == 0)
  try channel.writeOutbound(buffer(plain))
  #expect(try channel.readOutbound(as: ByteBuffer.self).map(bytes(of:)) == vector.outbound)
  try channel.writeInbound(buffer([]))
  #expect(try channel.readInbound(as: ByteBuffer.self)?.readableBytes == 0)
  try channel.writeInbound(buffer(vector.inbound))
  #expect(try channel.readInbound(as: ByteBuffer.self).map(bytes(of:)) == plain)
  _ = try? channel.finish()
}

// MARK: - Obfuscation and framing together

private let obfuscatedTransports: [MTProtoTransport] = [
  .abridged, .intermediate, .paddedIntermediate,
]

/// The accepting end of an obfuscated connection: the cipher under the frame
/// codec, as ``MTProtoTransportConfiguration`` stacks them.
private func acceptingPipeline(_ transport: MTProtoTransport) throws -> [any ChannelHandler] {
  let header = try MTProtoObfuscation.makeHandshake(
    transport: transport, secret: nil, dcId: nil, initPayload: initPayload
  ).header
  let accepted = try MTProtoObfuscation.acceptHandshake(received: header)
  return [
    MTProtoObfuscationHandler(
      encrypt: accepted.encrypt, decrypt: accepted.decrypt, transport: accepted.transport),
    decoder(transport),
    MTProtoFrameEncoder(transport: transport),
  ]
}

/// The initiator's two keystreams, positioned after the header.
private func initiatorStreams(
  _ transport: MTProtoTransport
) throws -> (encrypt: AESCTRStream, decrypt: AESCTRStream) {
  let handshake = try MTProtoObfuscation.makeHandshake(
    transport: transport, secret: nil, dcId: nil, initPayload: initPayload)
  return (handshake.encrypt, handshake.decrypt)
}

@Test(arguments: obfuscatedTransports)
func decodesAnObfuscatedStreamSplitAtEveryByteBoundary(_ transport: MTProtoTransport) throws {
  let stream = Stream(transport, payloadSizes: [8, 12, 16, 8])
  var cipher = try initiatorStreams(transport).encrypt
  let wire = cipher.apply(stream.wire)
  for split in 0...wire.count {
    let parts = [wire[..<split], wire[split...]].filter { !$0.isEmpty }
    #expect(
      try decode(parts, through: acceptingPipeline(transport)) == stream.payloads,
      "split at \(split)")
  }
}

@Test(arguments: obfuscatedTransports)
func decodesAnObfuscatedStreamArrivingInPieces(_ transport: MTProtoTransport) throws {
  let stream = Stream(transport, payloadSizes: largeSizes)
  var cipher = try initiatorStreams(transport).encrypt
  let wire = cipher.apply(stream.wire)
  for size in [wire.count, 1021, 4096] {
    #expect(
      try decode(chunks(wire, of: size), through: acceptingPipeline(transport))
        == stream.payloads,
      "\(size)-byte reads")
  }
  let small = Stream(transport, payloadSizes: smallSizes)
  cipher = try initiatorStreams(transport).encrypt
  let smallWire = cipher.apply(small.wire)
  for size in [1, 3, 7] {
    #expect(
      try decode(chunks(smallWire, of: size), through: acceptingPipeline(transport))
        == small.payloads,
      "\(size)-byte reads")
  }
}

@Test(arguments: [MTProtoTransport.abridged, .intermediate])
func obfuscatedFramesAreTheEncipheredClearFrames(_ transport: MTProtoTransport) throws {
  let payloads = [8, 508, 70_000, 12].map { pattern($0, seed: $0) }
  let wire = try write(payloads, through: acceptingPipeline(transport))
  // One buffer per frame, and deciphered they are the frames built by hand.
  #expect(wire.count == payloads.count)
  var cipher = try initiatorStreams(transport).decrypt
  #expect(wire.map { cipher.apply($0) } == payloads.map { frame($0, transport) })
}

@Test func malformedFramesAreRejectedUnderObfuscationToo() throws {
  var cipher = try initiatorStreams(.intermediate).encrypt
  let wire = cipher.apply(frame(hex("0102030405060708"), .intermediate) + [0, 0, 0, 0])
  let channel = EmbeddedChannel(handlers: try acceptingPipeline(.intermediate))
  #expect(throws: MTProtoTransportError.invalidFrameLength(0)) {
    try channel.writeInbound(buffer(wire))
  }
  #expect(try channel.readInbound(as: ByteBuffer.self).map(bytes(of:)) == hex("0102030405060708"))
  _ = try? channel.finish()
}
