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
  public enum Error: Swift.Error {
    case initFailed(Int32)
    case inflateFailed(Int32)
  }

  /// Inflates a gzip- (or zlib-) compressed buffer.
  public static func inflate(_ input: Data) throws -> Data {
    if input.isEmpty { return Data() }

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
        if produced > 0 { output.append(contentsOf: chunk[0..<produced]) }
      } while status != Z_STREAM_END && stream.avail_in > 0
      return status
    }

    guard result == Z_STREAM_END || result == Z_OK else {
      throw Error.inflateFailed(result)
    }
    return output
  }
}
