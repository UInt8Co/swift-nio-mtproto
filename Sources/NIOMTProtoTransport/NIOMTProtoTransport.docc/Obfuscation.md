# Obfuscation

The "obfuscated2" scheme, and where it sits in the pipeline.

## Overview

An obfuscated MTProto connection looks like 64 random bytes followed by an
undifferentiated stream of them. ``MTProtoObfuscationHandler`` (a
`ChannelDuplexHandler`) implements it. On `channelActive` it builds the 64-byte
init payload (``MTProtoObfuscation``):

- 64 random bytes whose first 8 are constrained so the preamble cannot be
  mistaken for another transport or for an HTTP request line;
- bytes `8..40` / `40..56` become the AES-256 **encryption** key / IV; the same
  ranges of the *reversed* payload become the **decryption** key / IV;
- the transport protocol tag is stamped at offset 56 (and an optional MTProxy
  DC id at offset 60);
- an optional MTProxy `secret` folds into the keys as `SHA256(key ‖ secret)`.

The payload is then encrypted and the wire header is sent as 56 plaintext bytes
followed by the last 8 ciphertext bytes. Every subsequent byte is encrypted or
decrypted with the connection's continuous AES-256-CTR keystreams, so the frame
codecs above the obfuscation handler see a plain stream.

`AESCTRStream` layers the stream state (a 128-bit big-endian counter plus a
leftover-keystream buffer) on top of swift-crypto's vetted, block-aligned
`AES._CTR`, so the counter persists correctly across arbitrarily-chunked reads
and writes.

## Pipeline order

``MTProtoTransportConfiguration/makeHandlers()`` returns the handlers in
head-to-tail (socket-to-application) order:

```
socket ─ obfuscation / clear-preamble ─ frame decoder ─ frame encoder ─ app
         └──────────── inbound: decrypt → deframe ───────────────────→
         ←──────────── outbound: frame → encrypt ────────────────────┘
```

The obfuscation (or clear-preamble) handler is closest to the socket so it
decrypts inbound bytes before framing and encrypts outbound bytes after it.

``MTProtoTransport/full`` cannot be obfuscated: it has no protocol tag to stamp
into the header, so there is nothing for the peer to recognise.
