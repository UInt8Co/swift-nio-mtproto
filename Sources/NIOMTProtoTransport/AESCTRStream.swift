import CryptoExtras

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// A stateful AES-256 counter-mode (CTR) keystream, applied to a byte stream in
/// arbitrarily-sized chunks.
///
/// MTProto transport obfuscation encrypts the *entire* connection as one
/// continuous AES-256-CTR stream whose counter persists across packets, so the
/// state a call leaves behind is what the next one starts from:
///
/// - a 16-byte big-endian counter block (initialised from the IV), incremented
///   as one 128-bit number for every block of keystream generated, and
/// - the keystream block in use, with how much of it has been spent.
///
/// CTR encryption and decryption are the same operation (XOR with the
/// keystream), so ``apply(_:)`` and its span forms serve both directions.
///
/// Only that state lives here. The cipher is BoringSSL's `AES_ctr128_encrypt`,
/// from the copy swift-crypto builds, which keeps exactly this state between
/// calls and enciphers from one buffer into another, or in place, without
/// allocating. swift-crypto's own `AES._CTR` only offers a one-shot form that
/// starts on a block boundary and returns a new `Data`.
public struct AESCTRStream {
  // BoringSSL's `AES_KEY`: 61 32-bit words, 4-byte aligned. SIMD64 is
  // fixed-size inline storage, so the stream stays a plain copyable value.
  private var schedule = SIMD64<UInt32>()
  /// The next counter block to feed to the cipher, big-endian.
  private var counter = SIMD16<UInt8>()
  /// The keystream block being spent, and how many of its bytes are gone.
  private var keystream = SIMD16<UInt8>()
  private var keystreamUsed: CUnsignedInt = 0

  /// Creates a keystream for a 32-byte AES-256 `key` and 16-byte initial
  /// counter `iv`.
  public init(key: Data, iv: Data) {
    precondition(key.count == 32, "AES-256 requires a 32-byte key, got \(key.count)")
    precondition(iv.count == 16, "AES-CTR requires a 16-byte IV, got \(iv.count)")
    let status = key.withUnsafeBytes { boringSSLAESSetEncryptKey($0.baseAddress!, 256, &schedule) }
    precondition(status == 0)
    for (index, byte) in iv.enumerated() { counter[index] = byte }
  }

  /// XORs `input` with the next keystream bytes and returns the result,
  /// advancing the stream state by `input.count` bytes.
  public mutating func apply(_ input: [UInt8]) -> [UInt8] {
    guard !input.isEmpty else { return [] }
    return [UInt8](unsafeUninitializedCapacity: input.count) { output, initialized in
      input.withUnsafeBytes { apply($0, into: UnsafeMutableRawBufferPointer(output)) }
      initialized = input.count
    }
  }

  /// XORs `input` with the next keystream bytes into the first
  /// `input.byteCount` bytes of `output`, which the caller owns, advancing the
  /// stream state by that many bytes. Nothing is allocated or copied on the
  /// way.
  public mutating func apply(_ input: RawSpan, into output: inout MutableRawSpan) {
    precondition(output.byteCount >= input.byteCount, "output is shorter than the input")
    input.withUnsafeBytes { input in
      output.withUnsafeMutableBytes { apply(input, into: $0) }
    }
  }

  /// XORs `bytes` with the next keystream bytes where they are, advancing the
  /// stream state by `bytes.byteCount` bytes.
  public mutating func apply(inPlace bytes: inout MutableRawSpan) {
    bytes.withUnsafeMutableBytes { apply(UnsafeRawBufferPointer($0), into: $0) }
  }

  /// The one place the cipher runs. `output` is at least as long as `input`,
  /// and is either `input` itself or does not overlap it.
  mutating func apply(_ input: UnsafeRawBufferPointer, into output: UnsafeMutableRawBufferPointer) {
    guard input.count > 0 else { return }
    precondition(output.count >= input.count)
    boringSSLAESCTR128Encrypt(
      input.baseAddress!, output.baseAddress!, input.count, &schedule, &counter, &keystream,
      &keystreamUsed)
  }
}

// BoringSSL's raw AES API (`<openssl/aes.h>`). swift-crypto builds BoringSSL
// into `CryptoExtras` on every platform, with its symbols prefixed, but does
// not export the module; these bind those symbols, as swift-mtproto's
// `AESIGE` does. If swift-crypto ever renames them, linking fails rather than
// anything at run time. BoringSSL dispatches to the CPU's AES instructions
// when present and to constant-time code otherwise.

@_extern(c, "CCryptoBoringSSL_AES_set_encrypt_key")
private func boringSSLAESSetEncryptKey(
  _ key: UnsafeRawPointer, _ bits: CUnsignedInt, _ schedule: UnsafeMutableRawPointer
) -> CInt

/// `AES_ctr128_encrypt(in, out, len, key, ivec, ecount_buf, num)`: `in` and
/// `out` may be the same pointer; `ivec` is the counter, incremented across
/// all 128 bits; `ecount_buf` and `num` are the keystream block in use and how
/// much of it is spent.
@_extern(c, "CCryptoBoringSSL_AES_ctr128_encrypt")
private func boringSSLAESCTR128Encrypt(
  _ input: UnsafeRawPointer, _ output: UnsafeMutableRawPointer, _ length: Int,
  _ schedule: UnsafeRawPointer, _ counter: UnsafeMutableRawPointer,
  _ keystream: UnsafeMutableRawPointer, _ keystreamUsed: UnsafeMutablePointer<CUnsignedInt>)
