#ifndef CZLIB_SHIM_H
#define CZLIB_SHIM_H

#include <zlib.h>

// `inflateInit2` is a macro in <zlib.h> (it passes the zlib version and the
// struct size), so it isn't importable from Swift. Re-expose it as a real
// function for the `windowBits` value we need (gzip/zlib auto-detect: 15 + 32).
static inline int czlib_inflateInit2(z_streamp strm, int windowBits) {
  return inflateInit2(strm, windowBits);
}

#endif /* CZLIB_SHIM_H */
