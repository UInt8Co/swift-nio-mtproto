# Connecting to a server

What ``MTProtoClient/connect()`` does, and what it needs from you.

## Overview

``MTProtoClient/connect()`` opens a `ClientBootstrap`, installs the transport
handlers from `NIOMTProtoTransport`, adds a channel handler that feeds an
``MTProtoClientConnection`` actor, and then waits until the session is usable —
either because the handshake finished or because a resumed session was accepted.
``MTProtoClientConfiguration/connectTimeout`` bounds that wait, which matters:
a server can complete the TCP connection and then never answer, and without the
bound `connect()` would hang rather than fail.

The event loop group defaults to `MultiThreadedEventLoopGroup.singleton`, not a
fresh group per client. A process that opens many clients at once would otherwise
oversubscribe its cores several times over.

## Trusting the server

``MTProtoClientConfiguration/rsaPublicKey`` is the trust anchor. During the
handshake the server offers the fingerprints of the keys it holds; the client
requires its own key to be among them, encrypts `p_q_inner_data` to that key with
the `RSA_PAD` layout, and only the holder of the matching private half can
complete Diffie–Hellman. If the fingerprint is missing the handshake fails with
``MTProtoClientHandshakeError/fingerprintNotOffered(_:)`` rather than proceeding.

A key in PEM form — either PKCS#1 or SPKI — goes through
``RSAPublicKey/init(pem:)``. ``MTProtoClientConfiguration/dhParameters`` defaults
to the well-known 2048-bit Telegram group and any other `p` is rejected.

## The transport

`MTProtoClient(host:port:configuration:transport:group:)` takes an
`MTProtoTransport`; `.intermediate` is the default and the reasonable choice.
Obfuscation is configured through the transport layer, not here.

## Calling methods

``MTProtoClient/invoke(_:)`` serializes a `TLFunction`, correlates the
`rpc_result` by `req_msg_id`, and decodes the reply into the function's declared
return type. An `rpc_error` surfaces as ``MTProtoRPCError`` with Telegram's code
and message; a call that outlives
``MTProtoClientConfiguration/requestTimeout`` throws instead of waiting forever.

Server-initiated messages that belong to no request — API updates — are handed to
``MTProtoClientConfiguration/onUnhandledMessage`` as boxed bytes, since only a
schema-aware caller can interpret them.
