import NIOMTProtoEncryption
import Testing

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

@Suite struct MTProtoGzipTests {
  // gzip -n over "hello MTProto", with a fixed header and checksum.
  let message = Data([
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0xf0, 0x0d, 0x09, 0x28,
    0xca, 0x2f, 0xc9, 0x07, 0x00, 0x29, 0x2d, 0xff, 0x9e, 0x0d,
    0x00, 0x00, 0x00,
  ])

  @Test func acceptsExactOutputLimit() throws {
    #expect(try MTProtoGzip.inflate(message, maximumOutputSize: 13) == Data("hello MTProto".utf8))
  }

  @Test func rejectsExpansionBeyondLimit() {
    #expect(throws: MTProtoGzip.Error.outputLimitExceeded(12)) {
      try MTProtoGzip.inflate(message, maximumOutputSize: 12)
    }
  }

  @Test func drainsOutputAcrossChunkBoundaries() throws {
    let compressed = try #require(
      Data(
        base64Encoded:
          "H4sIAAAAAAAAA+3BgQAAAACAILb9pRapCgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY3t4zZwCAAAA="
      ))
    #expect(
      try MTProtoGzip.inflate(compressed, maximumOutputSize: 32768)
        == Data(repeating: 65, count: 32768))
    #expect(throws: MTProtoGzip.Error.outputLimitExceeded(32767)) {
      try MTProtoGzip.inflate(compressed, maximumOutputSize: 32767)
    }
  }

  @Test func acceptsEmptyCompressedStreamWithZeroBudget() throws {
    let empty = Data([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    #expect(try MTProtoGzip.inflate(empty, maximumOutputSize: 0).isEmpty)
  }

  @Test func rejectsTruncatedStreamsAtEveryByte() {
    for count in 0..<message.count {
      #expect(throws: MTProtoGzip.Error.self) {
        try MTProtoGzip.inflate(message.prefix(count))
      }
    }
  }

  @Test func rejectsCorruptedTrailer() {
    var corrupt = message
    corrupt[corrupt.count - 8] ^= 1
    #expect(throws: MTProtoGzip.Error.self) {
      try MTProtoGzip.inflate(corrupt)
    }
  }
}
