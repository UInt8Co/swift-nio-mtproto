import MTProtoBaseSchema
import NIOConcurrencyHelpers
import NIOCore
import NIOMTProtoTransport
import NIOPosix
import TLCoding

#if canImport(FoundationEssentials)
  import FoundationEssentials
#else
  import Foundation
#endif

/// A high-level MTProto *client* over TCP.
///
/// ```swift
/// let client = MTProtoClient(
///   host: dc.host, port: dc.port,
///   configuration: .init(rsaPublicKey: dc.rsaKey, dcID: 2))
/// try await client.connect()
/// let config = try await client.invoke(TL.Help.GetConfig())
/// try await client.disconnect()
/// ```
///
/// It opens a `ClientBootstrap`, adds the (bidirectional) transport handlers
/// and a channel handler feeding an ``MTProtoClientConnection`` actor, runs
/// the auth-key handshake (or resumes a stored session), and then exposes a
/// generic `TLFunction` `invoke`. Independent of the API schema — the
/// `TLFunction` bound is satisfied by any generated method or a hand-rolled
/// one.
public final class MTProtoClient: Sendable {
  private let host: String
  private let port: Int
  private let transport: MTProtoTransport
  private let connection: MTProtoClientConnection
  private let group: EventLoopGroup
  private let connectTimeout: Duration?
  private let log: (@Sendable (String) -> Void)?

  private struct ChannelBox: @unchecked Sendable {
    var channel: Channel?
  }
  private let channelBox = NIOLockedValueBox(ChannelBox(channel: nil))

  /// - Parameters:
  ///   - transport: the framing to use (`intermediate` is the usual choice;
  ///     `full` adds a per-frame CRC).
  ///   - group: an event-loop group to run on, or nil to use the shared
  ///     process-wide singleton.
  public init(
    host: String,
    port: Int,
    configuration: MTProtoClientConfiguration,
    transport: MTProtoTransport = .intermediate,
    group: EventLoopGroup? = nil
  ) {
    self.host = host
    self.port = port
    self.transport = transport
    self.connection = MTProtoClientConnection(configuration: configuration)
    self.connectTimeout = configuration.connectTimeout
    self.log = configuration.log
    // Default to the process-wide singleton, not a fresh per-client group: a
    // test process (or a mesh of peer connections) opens many clients at once,
    // and a group each oversubscribes a small box's cores. Either way it is shared,
    // so we never shut it down.
    self.group = group ?? MultiThreadedEventLoopGroup.singleton
  }

  /// Connects, runs the handshake (or resumes), and returns once the session
  /// is usable.
  public func connect() async throws {
    let connection = self.connection
    let transport = self.transport
    let transportConfig = MTProtoTransportConfiguration(transport: transport)

    // Bound the TCP-connect phase by the same budget as the handshake. NIO's
    // ClientBootstrap otherwise applies a hidden 10s default: under a crowded
    // box the event loop can be starved by another connection's synchronous
    // handshake modexp long enough for that 10s timer (scheduled on the loop)
    // to fire before the connect completion is processed.
    let connectDeadline = connectTimeout.map(TimeAmount.init) ?? .minutes(5)
    let bootstrap = ClientBootstrap(group: group)
      .connectTimeout(connectDeadline)
      .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
      .channelInitializer { channel in
        channel.eventLoop.submit {
          var handlers = try transportConfig.makeHandlers()
          handlers.append(MTProtoClientChannelHandler(connection: connection))
          try channel.pipeline.syncOperations.addHandlers(handlers)
        }
      }

    let channel = try await bootstrap.connect(host: host, port: port).get()
    channelBox.withLockedValue { $0.channel = channel }
    log?("client: connected to \(host):\(port)")
    do {
      // The timeout is enforced inside the actor (a per-waiter task), not by
      // racing tasks here — withCheckedContinuation isn't cancellation-aware,
      // so a TaskGroup would await the stuck waiter forever on scope exit.
      try await connection.waitUntilReady(timeout: connectTimeout)
    } catch {
      try? await channel.close()
      throw error
    }
  }

  /// Sends a boxed `TLFunction` and decodes its boxed `rpc_result`.
  public func invoke<F: TLFunction>(_ function: F) async throws -> F.ReturnType {
    let resultBytes = try await connection.invoke(function.tlSerialized())
    return try F.ReturnType(tlData: resultBytes)
  }

  /// Sends already-serialized boxed query bytes, returning the boxed result
  /// bytes — the schema-agnostic entry point, for tunnelling opaque queries.
  public func invokeRaw(_ queryBody: Data) async throws -> Data {
    try await connection.invoke(queryBody)
  }

  /// Non-secret binding for an application proof tied to this live session.
  public func sessionBinding() async -> MTProtoSessionBinding? {
    await connection.sessionBinding()
  }

  /// One explicit `ping` round-trip.
  public func ping() async throws {
    try await connection.ping()
  }

  /// Gracefully tears the connection down (best-effort `destroy_session`,
  /// then closes the channel).
  public func disconnect() async throws {
    await connection.prepareDisconnect()
    let channel = channelBox.withLockedValue { box -> Channel? in
      let channel = box.channel
      box.channel = nil
      return channel
    }
    try? await channel?.close()
    // The group is either the shared singleton or caller-owned; never ours to
    // shut down.
  }
}
