# Contributing

Thanks for your interest in swift-nio-mtproto.

## Building and testing

```sh
swift build
swift test
```

The test suite needs no network and no credentials: the RSA key it uses is
committed under `Fixtures/`.

## Formatting

The repository is formatted with the toolchain's `swift-format` and the committed
`.swift-format` configuration. CI runs the lint, so run this before opening a
pull request:

```sh
swift format --in-place --recursive Package.swift Sources Tests
```

## Scope

This package implements MTProto's *wire protocol* and nothing above it — no
users, chats, messages, or API-schema types. TL serialization, the crypto
primitives and the schema generator live in
[swift-mtproto](https://github.com/UInt8Co/swift-mtproto); a change that belongs
there is better made there.

The split between modules is worth preserving when adding code:

- `NIOMTProtoTransport` depends on no crypto beyond AES-CTR and no TL at all.
- `NIOMTProtoEncryption` knows the MTProto service schema, never an API schema,
  and nothing in it may assume which end of a connection it is on.
- `MTProtoClientKit` deals in *boxed bytes* and generic `TLFunction` values, so
  it cannot be tied to one API schema.

## Pull requests

- Keep the state machines testable in isolation. Anything with protocol-visible
  behaviour should be reachable without a socket — that is why the handshake,
  the envelope codec and the validators are values rather than handlers.
- Add tests alongside behaviour changes. Byte-exact expectations are preferred
  over round-trip-only tests for anything that appears on the wire.
- Where behaviour follows Telegram's documentation, cite the page in a comment;
  where it follows what real clients actually do instead, say so, because those
  two things differ often enough to matter.
- Never cancel a `Task.sleep`. The concurrency runtime leaks a few hundred
  bytes every time a sleeping task is cancelled and never reclaims it
  (swiftlang/swift#60441), so a timer on a per-query path grows a long-lived
  connection without bound. End a wait some other way: let the deadline run
  itself out and find its entry gone, orphan it with a generation tag, or have a
  loop read the connection's phase on its next wake. This connection does all
  three.
