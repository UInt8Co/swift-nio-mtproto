# ``NIOMTProtoTransport``

Carry MTProto payloads over a TCP connection with SwiftNIO.

## Overview

MTProto's [transports](https://core.telegram.org/mtproto/mtproto-transports) are
the envelopes below the protocol itself: they turn a raw byte stream into a
stream of discrete payloads, optionally disguised so a middlebox cannot tell
what the connection carries. This module implements them as SwiftNIO channel
handlers, and nothing else — it does not interpret a payload's contents. Pair it
with an MTProto message layer for that, such as `MTProtoClientKit`.

A client picks its transport and adds the handlers to its pipeline:

```swift
import NIOCore
import NIOPosix
import NIOMTProtoTransport

let bootstrap = ClientBootstrap(group: group)
  .channelInitializer { channel in
    channel.pipeline.addMTProtoTransportHandlers(
      MTProtoTransportConfiguration(
        transport: .intermediate,
        obfuscation: .init()        // omit for a clear-text transport
      )
    ).flatMap {
      channel.pipeline.addHandler(MyMTProtoSessionHandler())   // sees plain payloads
    }
  }
```

The framing is symmetric, so the same handlers serve the accepting end of a
connection — an MTProxy, a relay, a test double. What differs is that the
accepting end does not know the initiator's choice in advance: it must read the
preamble (or ``MTProtoObfuscation/acceptHandshake(received:secret:)``) before it
can install the matching framing.

## Topics

### Essentials

- <doc:Transports>
- <doc:Obfuscation>

### Configuring a pipeline

- ``MTProtoTransport``
- ``MTProtoTransportConfiguration``
- ``NIOCore/ChannelPipeline/addMTProtoTransportHandlers(_:)``

### Handlers

- ``MTProtoFrameDecoder``
- ``MTProtoFrameEncoder``
- ``MTProtoObfuscationHandler``
- ``MTProtoClearPreambleHandler``

### Support

- ``MTProtoObfuscation``
- ``AESCTRStream``
- ``MTProtoTransportError``
