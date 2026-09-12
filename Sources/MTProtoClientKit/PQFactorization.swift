import MTProtoCrypto

/// Factorization of the handshake's `pq` proof-of-work challenge — the client
/// side of `MTProtoCrypto.PQChallenge` (which only *generates* challenges).
/// A candidate to move upstream beside it.
public enum PQFactorization {
  /// Factors the ~62-bit semiprime `pq` (two ~31-bit primes, as
  /// `PQChallenge` produces) into `p < q`, or nil when `pq` is not such a
  /// semiprime. Pollard's rho with Floyd cycle finding — microseconds for
  /// the sizes MTProto uses.
  public static func factor(_ pq: UInt64) -> (p: UInt32, q: UInt32)? {
    guard pq > 3 else { return nil }
    // Pull out small prime factors first; rho requires an odd composite.
    for small: UInt64 in [2, 3, 5, 7] where pq % small == 0 {
      let other = pq / small
      return factorPair(small, other)
    }
    // resPQ is unauthenticated. A large prime can make rho's cycle finding
    // run for billions of iterations, so rule primes out first.
    guard !isPrime(pq) else { return nil }

    var addend: UInt64 = 1
    // Bound each polynomial as well as the retries. Bounding only the outer
    // loop does not bound work spent inside a hostile challenge's first cycle.
    while addend <= 32 {
      func step(_ x: UInt64) -> UInt64 {
        UInt64((UInt128(mulmod(x, x, pq)) + UInt128(addend)) % UInt128(pq))
      }
      var x: UInt64 = 2
      var y: UInt64 = 2
      var divisor: UInt64 = 1
      var iterations = 0
      while divisor == 1, iterations < 131_072 {
        x = step(x)
        y = step(step(y))
        divisor = gcd(x > y ? x - y : y - x, pq)
        iterations += 1
      }
      if divisor > 1, divisor != pq {
        return factorPair(divisor, pq / divisor)
      }
      addend += 1  // unlucky cycle; retry with a different polynomial
    }
    return nil
  }

  /// Deterministic Miller–Rabin for all UInt64 inputs. These seven witnesses
  /// cover the complete range, including primes close to UInt64.max.
  private static func isPrime(_ value: UInt64) -> Bool {
    var d = value - 1
    let shifts = d.trailingZeroBitCount
    d >>= shifts
    for witness: UInt64 in [2, 325, 9375, 28178, 450775, 9_780_504, 1_795_265_022] {
      var base = witness % value
      if base == 0 { continue }
      var exponent = d
      var x: UInt64 = 1
      while exponent > 0 {
        if exponent & 1 == 1 { x = mulmod(x, base, value) }
        base = mulmod(base, base, value)
        exponent >>= 1
      }
      if x == 1 || x == value - 1 { continue }
      var passed = false
      for _ in 1..<shifts {
        x = mulmod(x, x, value)
        if x == value - 1 {
          passed = true
          break
        }
      }
      if !passed { return false }
    }
    return true
  }

  /// Orders and narrows a factor pair, rejecting non-prime or >32-bit
  /// factors (i.e. inputs that aren't a `PQChallenge`-shaped semiprime).
  private static func factorPair(_ a: UInt64, _ b: UInt64) -> (p: UInt32, q: UInt32)? {
    let (lo, hi) = (min(a, b), max(a, b))
    guard lo > 1, hi <= UInt64(UInt32.max) else { return nil }
    let (p, q) = (UInt32(lo), UInt32(hi))
    guard PQChallenge.isPrime(p), PQChallenge.isPrime(q) else { return nil }
    return (p, q)
  }

  private static func mulmod(_ a: UInt64, _ b: UInt64, _ m: UInt64) -> UInt64 {
    UInt64((UInt128(a) * UInt128(b)) % UInt128(m))
  }

  private static func gcd(_ a: UInt64, _ b: UInt64) -> UInt64 {
    var (a, b) = (a, b)
    while b != 0 { (a, b) = (b, a % b) }
    return a
  }
}
