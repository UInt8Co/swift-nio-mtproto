# Transports and framing

The four TCP envelopes, and the two handlers that apply them.

## Overview

``MTProtoTransport`` selects the envelope. All four documented transports are
implemented:

| Transport | Magic / tag | Envelope |
|---|---|---|
| ``MTProtoTransport/abridged`` | `0xef` / `0xefefefef` | 1- or 4-byte length (in 4-byte words). Lightest. |
| ``MTProtoTransport/intermediate`` | `0xeeeeeeee` | 4-byte little-endian length. |
| ``MTProtoTransport/paddedIntermediate`` | `0xdddddddd` | 4-byte length covering 0–15 random trailing pad bytes. |
| ``MTProtoTransport/full`` | — | length + seqno + payload + CRC32. No magic; cannot be obfuscated. |

Framing is split into two composable handlers so each direction stays simple:

- ``MTProtoFrameEncoder`` (`ChannelOutboundHandler`) wraps each outbound payload
  in the envelope. For `.full` it maintains the per-connection send sequence
  number and appends the CRC32; for `.paddedIntermediate` it adds the random
  padding.
- ``MTProtoFrameDecoder`` (`ByteToMessageDecoder`) strips the envelope and emits
  each payload, buffering partial reads until a frame is complete. It validates
  the `.full` CRC32 and sequence number, enforces
  ``MTProtoTransportConfiguration/maximumFrameLength``, and surfaces the bare
  4-byte negative
  [transport error codes](https://core.telegram.org/mtproto/mtproto-transports)
  (`-404`, `-429`, `-444`, …) as ``MTProtoTransportError/serverError(code:)``.

> Note: The `.paddedIntermediate` decoder emits the payload *with* its trailing
> padding, since the pad length is not recoverable from the framing alone. The
> MTProto message layer determines the true length from the message structure
> and ignores the remainder.

## Preambles

Every transport but `.full` begins with a magic value the client sends once, so
the server can recognise the framing. On a clear-text connection
``MTProtoClearPreambleHandler`` writes it on `channelActive`; when the connection
is obfuscated the tag is carried inside the obfuscation header instead (see
<doc:Obfuscation>).

## WebSocket

Browsers cannot open a raw TCP connection, and Telegram's web clients therefore
speak MTProto over WebSocket. Nothing about the framing changes: once the HTTP
upgrade is done, each WebSocket binary frame carries exactly the byte stream a
TCP connection would have carried — a preamble or obfuscation header, then
transport frames — so the handlers here apply unchanged above a frame codec that
unwraps them.
