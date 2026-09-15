// swift-tools-version: 6.3

import PackageDescription

let package = Package(
  name: "swift-nio-mtproto",
  platforms: [.macOS(.v15), .iOS(.v18), .tvOS(.v18), .watchOS(.v11), .macCatalyst(.v18)],
  products: [
    .library(name: "NIOMTProtoTransport", targets: ["NIOMTProtoTransport"]),
    .library(name: "NIOMTProtoEncryption", targets: ["NIOMTProtoEncryption"]),
    .library(name: "MTProtoClientKit", targets: ["MTProtoClientKit"]),
  ],
  dependencies: [
    .package(url: "https://github.com/UInt8Co/swift-mtproto.git", from: "2.0.0"),
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.100.0"),
  ],
  targets: [
    // A tiny C shim over the system zlib, used by ``MTProtoGzip``.
    .target(
      name: "CZlib"
    ),
    // The MTProto transport framing (TCP intermediate/abridged + WebSocket),
    // independent of the crypto/session layers.
    .target(
      name: "NIOMTProtoTransport",
      dependencies: [
        .product(name: "MTProtoUtils", package: "swift-mtproto"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "Crypto", package: "swift-crypto"),
        .product(name: "CryptoExtras", package: "swift-crypto"),
      ]
    ),
    .testTarget(
      name: "NIOMTProtoTransportTests",
      dependencies: [
        "NIOMTProtoTransport",
        .product(name: "MTProtoUtils", package: "swift-mtproto"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOEmbedded", package: "swift-nio"),
      ]
    ),
    // The MTProto message layer: the encrypted-message envelope, the DH
    // parameters the auth-key handshake runs over, session persistence, and
    // `gzip_packed` inflate.
    .target(
      name: "NIOMTProtoEncryption",
      dependencies: [
        "CZlib",
        .product(name: "TLCoding", package: "swift-mtproto"),
        .product(name: "MTProtoCrypto", package: "swift-mtproto"),
      ]
    ),
    .testTarget(
      name: "NIOMTProtoEncryptionTests",
      dependencies: [
        "NIOMTProtoEncryption",
        .product(name: "MTProtoCrypto", package: "swift-mtproto"),
        .product(name: "TLCoding", package: "swift-mtproto"),
      ]
    ),
    // The MTProto *client* half: the handshake initiator, the encrypted-session
    // crypto/rules of a well-behaved client (msg_id/seq_no, salts, acks, pings,
    // rpc_result correlation), and a NIO ClientBootstrap pipeline. Independent
    // of the API schema (callers pass boxed query bytes / TLFunction values).
    .target(
      name: "MTProtoClientKit",
      dependencies: [
        "NIOMTProtoTransport",
        "NIOMTProtoEncryption",
        .product(name: "TLCoding", package: "swift-mtproto"),
        .product(name: "MTProtoBaseSchema", package: "swift-mtproto"),
        .product(name: "MTProtoCrypto", package: "swift-mtproto"),
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOPosix", package: "swift-nio"),
        .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .testTarget(
      name: "MTProtoClientKitTests",
      dependencies: [
        "MTProtoClientKit",
        "NIOMTProtoEncryption",
        .product(name: "NIOCore", package: "swift-nio"),
        .product(name: "NIOEmbedded", package: "swift-nio"),
        .product(name: "TLCoding", package: "swift-mtproto"),
        .product(name: "MTProtoBaseSchema", package: "swift-mtproto"),
        .product(name: "MTProtoCrypto", package: "swift-mtproto"),
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
  ],
  swiftLanguageModes: [.v6]
)
