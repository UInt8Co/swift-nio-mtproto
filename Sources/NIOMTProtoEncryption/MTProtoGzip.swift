import CZlib

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// Inflate for `gzip_packed` message bodies.
///
/// Either side of a connection may compress a message body and send it as
/// `gzip_packed` (<https://core.telegram.org/mtproto/service_messages>), so
/// unpacking one is part of reading the message layer. Only inflate is needed:
/// compressing outbound bodies is optional and no peer requires it.
public enum MTProtoGzip {
  public enum Error: Swift.Error, Equatable {
    case initFailed(Int32)
    case inflateFailed(Int32)
    case inputTooLarge
    case outputLimitExceeded(Int)
  }

  /// Inflates a complete gzip- (or zlib-) compressed buffer, limiting its
  /// expanded size before appending each output chunk. Callers processing
  /// nested wrappers should share a budget across all expansions.
  public static func inflate(_ input: Data, maximumOutputSize: Int = 1 << 24) throws -> Data {
    guard maximumOutputSize >= 0 else { throw Error.outputLimitExceeded(maximumOutputSize) }
    guard input.count <= Int(uInt.max) else { throw Error.inputTooLarge }

    var stream = z_stream()
    // 15 (max window) + 32 → automatic gzip/zlib header detection.
    guard czlib_inflateInit2(&stream, 15 + 32) == Z_OK else {
      throw Error.initFailed(Z_STREAM_ERROR)
    }
    defer { inflateEnd(&stream) }

    var output = Data()
    let chunkSize = 16 * 1024
    var chunk = [UInt8](repeating: 0, count: chunkSize)

    let result: Int32 = try input.withUnsafeBytes { rawIn -> Int32 in
      stream.next_in = UnsafeMutablePointer(
        mutating: rawIn.bindMemory(to: UInt8.self).baseAddress)
      stream.avail_in = uInt(input.count)

      var status = Z_OK
      repeat {
        let produced: Int = try chunk.withUnsafeMutableBytes { rawOut -> Int in
          stream.next_out = rawOut.bindMemory(to: UInt8.self).baseAddress
          stream.avail_out = uInt(chunkSize)
          status = CZlib.inflate(&stream, Z_NO_FLUSH)
          guard status == Z_OK || status == Z_STREAM_END else {
            throw Error.inflateFailed(status)
          }
          return chunkSize - Int(stream.avail_out)
        }
        guard produced <= maximumOutputSize - output.count else {
          throw Error.outputLimitExceeded(maximumOutputSize)
        }
        if produced > 0 { output.append(contentsOf: chunk[0..<produced]) }
        // Even after input is consumed, zlib may have buffered output. Keep
        // draining it until the checksum/trailer has been verified; truncated
        // input eventually returns Z_BUF_ERROR instead of a partial success.
      } while status != Z_STREAM_END
      return status
    }

    guard result == Z_STREAM_END else {
      throw Error.inflateFailed(result)
    }
    return output
  }
}
