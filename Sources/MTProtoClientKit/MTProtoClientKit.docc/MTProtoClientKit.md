# ``MTProtoClientKit``

Connect to an MTProto server and call methods on it.

## Overview

This is the client half of the stack: the handshake initiator, the session rules
a well-behaved client owes the server, and a NIO `ClientBootstrap` that ties them
to a socket. Give it a host, a port and the server's RSA public key, and it hands
you an `async` `invoke`.

```swift
import MTProtoClientKit

let client = MTProtoClient(
  host: "149.154.167.50", port: 443,
  configuration: .init(rsaPublicKey: serverKey, dcID: 2))

try await client.connect()
let config = try await client.invoke(TL.Help.GetConfig())
try await client.disconnect()
```

It is **independent of the API schema**: the `invoke` bound is
`TLFunction`, satisfied by any type a schema generator emits or one you write by
hand, and ``MTProtoClient/invokeRaw(_:)`` takes already-boxed bytes for
tunnelling. Nothing here needs to know what a `help.getConfig` is.

The pieces are separable, and each is a synchronous value or a plain actor rather
than a pipeline: ``MTProtoClientHandshake`` and ``MTProtoClientSessionCrypto`` are
state machines over message bodies, ``MTProtoClientConnection`` is the
transport-agnostic session actor, and ``MTProtoClient`` is the only part that
knows about sockets. A different transport — an existing WebSocket, a test
harness, an in-process pair — can drive the connection actor directly.

## Auth keys outlive connections

A handshake is expensive and its result is reusable.
``MTProtoClientConfiguration/onSessionEstablished`` fires with the negotiated
keys; persist them and pass them back as
``MTProtoClientConfiguration/resumeSession`` next time to skip the exchange
entirely. A salt that went stale in the meantime recovers by itself.

## Topics

### Essentials

- <doc:ConnectingToAServer>
- <doc:ClientSessionRules>

### Connecting

- ``MTProtoClient``
- ``MTProtoClientConfiguration``
- ``MTProtoClientConnection``

### State machines

- ``MTProtoClientHandshake``
- ``MTProtoClientSessionCrypto``
- ``MTProtoClientInboundValidator``

### Client-side crypto

- ``RSAPublicKey``
- ``PQFactorization``

### Errors

- ``MTProtoClientError``
- ``MTProtoClientHandshakeError``
- ``MTProtoClientSessionError``
- ``MTProtoRPCError``
