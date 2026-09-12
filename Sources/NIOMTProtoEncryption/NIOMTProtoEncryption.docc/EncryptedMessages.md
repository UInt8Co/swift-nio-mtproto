# Encrypted messages

The MTProto 2.0 envelope, and what has to be true of it.

## Overview

Once an auth key exists, every message travels as

```
auth_key_id ‖ msg_key ‖ AES-256-IGE(salt ‖ session_id ‖ msg_id ‖ seq_no ‖ length ‖ body ‖ padding)
```

``MTProtoEncryptedMessage`` is that codec. It verifies `msg_key` in **constant
time** — `msg_key` is the integrity tag, so its verification must not leak where
it first differs — enforces the 12–1024-byte padding range, and encodes and
decodes both directions, since the two differ only in which slice of the auth key
the KDF uses. Plaintext bodies (the handshake's, with `auth_key_id = 0`) are
``MTProtoPlainMessage``.

A body may arrive compressed as `gzip_packed`, in either direction; unpacking one
is ``MTProtoGzip/inflate(_:maximumOutputSize:)``. Inflation requires a complete
stream, including its checksum, and defaults to a 16 MiB output limit. Callers
may pass a different limit; recursive/container dispatch must share a remaining
budget across sibling and nested compressed bodies.

## Resuming a session

A reconnecting client presents an `auth_key_id` from an earlier handshake rather
than repeating the exchange, so the key has to outlive the connection.
``MTProtoAuthKeyStore`` is the seam: ``InMemoryAuthKeyStore`` ships here, and
anything durable can be supplied instead. The stored ``MTProtoStoredSession``
carries the **server salt** alongside the key, so a reconnect keeps its salt
across a restart instead of paying a `bad_server_salt` round trip. For a PFS
temporary key it also carries the expiry, and ``MTProtoTempKeyBinding`` records
which permanent key it was bound to — the identity a bound temporary key acts
under.

## Reading a msg_id

`msg_id`s are not opaque: the high 32 bits are unix time, and the low bits carry
the direction (`≡ 0 (mod 4)` from the client, `≡ 1` for replies, `≡ 3` for
server-initiated pushes). Both ends are expected to reject an id whose embedded
time is too far in the past (a replay) or the future (clock skew), and to
remember which ids they have seen so a captured message cannot be replayed. The
client's half of that lives in `MTProtoClientKit`.
