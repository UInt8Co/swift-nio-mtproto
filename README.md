# swift-nio-mtproto

Applications can use `MTProtoClient.sessionBinding()` to bind authentication
proofs to the current transport. It exposes only the auth-key and session IDs;
reconnecting creates a new session ID even when the auth key is resumed.

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FUInt8Co%2Fswift-nio-mtproto%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/UInt8Co/swift-nio-mtproto)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FUInt8Co%2Fswift-nio-mtproto%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/UInt8Co/swift-nio-mtproto)

A [SwiftNIO](https://github.com/apple/swift-nio) transport for
[MTProto](https://core.telegram.org/mtproto), the protocol Telegram speaks: the
TCP framing and obfuscation, the auth-key handshake, the encrypted-message
session, and a client that sits on top.

```swift
.package(url: "https://github.com/UInt8Co/swift-nio-mtproto", from: "1.0.0")
```

## What this is

This is a programmatic implementation of MTProto's wire protocol — a set of
building blocks, closer to a protocol library than to a Telegram client. It knows
nothing about users, chats or messages: it moves *boxed TL bytes* between two
endpoints and leaves their meaning to you. Pair it with
[swift-mtproto](https://github.com/UInt8Co/swift-mtproto), which provides the TL
serialization, the crypto primitives, and a generator that turns Telegram's API
schema into Swift.

Connect to a data center, handshake, resume a stored session, and `await` a
method call.

```swift
import MTProtoClientKit

let client = MTProtoClient(
  host: dc.host, port: dc.port,
  configuration: .init(rsaPublicKey: dc.rsaKey, dcID: dc.id))

try await client.connect()
let config = try await client.invoke(TL.Help.GetConfig())
try await client.disconnect()
```

Underneath, each layer is a value or a state machine that is a pure function of
its inputs, with a NIO handler that drives it — so the framing, the handshake and
the envelope are all testable without a socket, and reusable outside the client
(the transport framing and the envelope codec are direction-agnostic, as MTProto
itself is).

## Modules

| Module | What it is |
|---|---|
| `NIOMTProtoTransport` | The [MTProto transports](https://core.telegram.org/mtproto/mtproto-transports) as NIO handlers: abridged / intermediate / padded-intermediate / full framing, and "obfuscated2" obfuscation with MTProxy secrets — initiating the handshake or accepting one |
| `NIOMTProtoEncryption` | The MTProto 2.0 message layer: the encrypted envelope with constant-time `msg_key` verification, the DH group and its safe-range checks, `gzip_packed` inflate, and a session store for reconnects (including PFS temporary-key bindings) |
| `MTProtoClientKit` | A client: handshake initiator, session rules (`msg_id`/`seq_no`, salt adoption, acks, pings, inbound validation, `rpc_result` correlation), and a `ClientBootstrap` wrapper exposing `async` `invoke` |

Every module is independent of any particular TL API schema — `invoke` is generic
over `TLFunction` and updates are handed back as boxed bytes — so the same code
serves the public Telegram API, a private schema, or a test double.

## Documentation

Each module carries a DocC catalog covering the transports, the obfuscation
handshake, the encrypted envelope and the session rules:

```sh
swift package --allow-writing-to-directory ./docs \
  generate-documentation --target MTProtoClientKit --output-path ./docs
```

(That needs [swift-docc-plugin](https://github.com/swiftlang/swift-docc-plugin)
added to your checkout, or Xcode's *Build Documentation*.) The sources are
`Sources/<Module>/<Module>.docc`, and read fine as Markdown on their own.

## Platforms

macOS 15+, iOS 18+, tvOS 18+, watchOS 11+, and Linux (glibc or musl). Swift 6.3
toolchain, language mode 6 — there is no support for earlier language modes.

## Tests

```sh
swift test
```

It needs no network and no credentials. The suite covers byte-exact framing for
every transport, the AES-256-CTR keystream against the NIST SP 800-38A F.5
vectors, the obfuscation handshake layout, the RSA layouts the handshake uses
(raw and RSA_PAD, plus signing), `pq` factorization, envelope round-trips in both
directions with tampering rejected, and the session store's eviction.

## License

MIT. See [LICENSE](LICENSE).
