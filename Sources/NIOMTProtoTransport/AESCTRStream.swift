import Crypto
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
/// continuous AES-256-CTR stream whose counter persists across packets. The
/// one-shot `AES._CTR` primitive from `swift-crypto` always starts at a block
/// boundary, so this type layers the missing stream state on top of it:
///
/// - a 16-byte big-endian counter block (initialised from the IV), advanced by
///   the number of whole blocks consumed so far, and
/// - a buffer of leftover keystream bytes from the final, partially-consumed
///   block, applied first on the next call.
///
/// CTR encryption and decryption are the same operation (XOR with the
/// keystream), so ``apply(_:)`` serves both directions.
public struct AESCTRStream {
  private let key: SymmetricKey
  /// The next counter block to feed to the cipher, big-endian.
  private var counter: [UInt8]
  /// Keystream bytes generated but not yet consumed (tail of the last block).
  private var keystreamRemainder: [UInt8] = []

  /// Creates a keystream for a 32-byte AES-256 `key` and 16-byte initial
  /// counter `iv`.
  public init(key: Data, iv: Data) {
    precondition(key.count == 32, "AES-256 requires a 32-byte key, got \(key.count)")
    precondition(iv.count == 16, "AES-CTR requires a 16-byte IV, got \(iv.count)")
    self.key = SymmetricKey(data: key)
    self.counter = [UInt8](iv)
  }

  /// XORs `input` with the next keystream bytes and returns the result,
  /// advancing the stream state by `input.count` bytes.
  public mutating func apply(_ input: [UInt8]) -> [UInt8] {
    guard !input.isEmpty else { return [] }
    var output = [UInt8]()
    output.reserveCapacity(input.count)

    var index = 0
    // 1. Spend any leftover keystream from the previous block first.
    if !keystreamRemainder.isEmpty {
      let take = min(keystreamRemainder.count, input.count)
      for i in 0..<take {
        output.append(input[i] ^ keystreamRemainder[i])
      }
      keystreamRemainder.removeFirst(take)
      index = take
    }

    // 2. Generate fresh keystream for the rest, a whole number of blocks at a
    //    time, and keep the unused tail of the final block for next time.
    let remaining = input.count - index
    if remaining > 0 {
      let blocks = (remaining + 15) / 16
      let keystream = keystreamBlocks(blocks)
      for i in 0..<remaining {
        output.append(input[index + i] ^ keystream[i])
      }
      advanceCounter(byBlocks: blocks)
      if keystream.count > remaining {
        keystreamRemainder = Array(keystream[remaining...])
      }
    }
    return output
  }

  // MARK: - Keystream generation

  /// Produces `blocks` × 16 keystream bytes for the current counter value by
  /// encrypting zeros (CTR keystream = E(counter) ⊕ 0).
  private func keystreamBlocks(_ blocks: Int) -> [UInt8] {
    let zeros = Data(count: blocks * 16)
    // Valid by construction: 32-byte key, 16-byte nonce — never throws.
    let nonce = try! AES._CTR.Nonce(nonceBytes: counter)
    let keystream = try! AES._CTR.encrypt(zeros, using: key, nonce: nonce)
    return [UInt8](keystream)
  }

  /// Adds `blocks` to the 16-byte big-endian counter, matching the full
  /// 128-bit increment performed by BoringSSL's `AES_ctr128_encrypt`.
  private mutating func advanceCounter(byBlocks blocks: Int) {
    var add = UInt64(blocks)
    var carry: UInt64 = 0
    var i = 15
    while i >= 0, add > 0 || carry > 0 {
      let sum = UInt64(counter[i]) + (add & 0xff) + carry
      counter[i] = UInt8(sum & 0xff)
      carry = sum >> 8
      add >>= 8
      i -= 1
    }
  }
}
