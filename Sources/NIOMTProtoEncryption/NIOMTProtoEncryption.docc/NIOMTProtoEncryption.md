# ``NIOMTProtoEncryption``

The MTProto 2.0 message layer: the encrypted envelope, the DH group the auth-key
handshake runs over, and session persistence.

## Overview

Between the transport framing and anything resembling an API sit two things: the
Diffie–Hellman exchange that produces an *auth key*
(<https://core.telegram.org/mtproto/auth_key>), and the encrypted envelope every
subsequent message travels in
(<https://core.telegram.org/mtproto/description>). This module holds the parts of
both that neither end of a connection can differ on — the envelope codec, the DH
parameters, the negotiated keys, the store they are resumed from, and
`gzip_packed` inflate. `MTProtoClientKit` builds the client on top.

```
            ┌─────────────────────────────────────────────┐
  socket ── │ NIOMTProtoTransport                         │  framing + obfuscation
            ├─────────────────────────────────────────────┤
            │ NIOMTProtoEncryption                        │  envelope + DH + keys
            ├─────────────────────────────────────────────┤
            │ MTProtoClientKit                            │  handshake, session
            └─────────────────────────────────────────────┘
```

Everything here is a value or a pure function of its inputs, so it can be driven
straight from a test without a socket. It deliberately knows nothing about the
Telegram *API* schema: the handshake's TL combinators come from swift-mtproto's
`MTProtoBaseSchema` — the low-level MTProto service schema alone.

## The DH group

``MTProtoDHParameters`` is a value, not a constant, so a deployment can configure
or rotate its group — but the well-known 2048-bit Telegram group is
``MTProtoDHParameters/telegram2048``, and a client that ships it as a trusted
constant will reject anything else. A peer offering a different `p` is
effectively offering an untrusted one. The type also carries the *safe range*
check Telegram's security guidelines demand of a DH public value
(`2^{2048-64} < g < p − 2^{2048-64}`, not merely `1 < g < p−1`).

## Topics

### Essentials

- <doc:EncryptedMessages>

### The envelope

- ``MTProtoEncryptedMessage``
- ``MTProtoPlainMessage``
- ``MTProtoGzip``

### Keys

- ``MTProtoDHParameters``
- ``MTProtoSessionKeys``
- ``int128Data(_:)``
- ``int256Data(_:)``

### Persistence

- ``MTProtoAuthKeyStore``
- ``InMemoryAuthKeyStore``
- ``MTProtoStoredSession``
- ``MTProtoTempKeyBinding``

### Utilities

- ``randomData(_:)``
