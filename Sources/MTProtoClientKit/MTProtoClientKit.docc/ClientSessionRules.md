# The rules a client owes the server

Message ids, salts, acknowledgements and pings — the parts a naïve client skips
and then mysteriously gets disconnected for.

## Overview

MTProto expects specific behaviour from a client beyond "encrypt and send".
``MTProtoClientConnection`` implements it, so a caller writing `try await
client.invoke(…)` never sees any of it:

- **Message ids.** Client `msg_id`s are `≡ 0 mod 4`, monotonically increasing,
  and derived from the server's clock — the offset learned during the handshake
  is applied to every subsequent id. A client whose clock is wrong and does not
  correct for it will have its messages rejected as out of window.
- **`rpc_result` correlation.** Replies name the `req_msg_id` they answer, and
  arrive in any order, possibly inside a `msg_container` or `gzip_packed`. Both
  wrappers are unpacked before dispatch.
- **Inbound validation and dedup.** ``MTProtoClientInboundValidator`` applies the
  mirror image of the server's checks to what arrives, so a duplicated or
  out-of-window message cannot be delivered twice. Eviction retains a lower
  bound on accepted ids, so filling the bounded cache cannot re-enable an old
  captured message.
- **Inbound resource limits.** Containers allow at most 1024 messages; wrapper
  nesting stops at 32 levels and each received envelope shares a 16 MiB
  inflation budget. The channel closes if pending processing exceeds 32 MiB or
  1024 messages. Handshake `pq` inputs are at most eight bytes, and factorization
  bounds both polynomial retries and their iteration counts.
- **Salts.** `bad_server_salt`, `new_session_created` and `future_salts` all
  carry a salt to adopt; the request that triggered a `bad_server_salt` is
  retried with the corrected one rather than surfaced as a failure.
- **`bad_msg_notification`.** Codes 16/20 correct the clock and resend the
  rejected message. Codes 17/32/33 start a fresh protocol session to reset the
  message-id or sequence counter, then resend all pending queries and explicit
  pings. Malformed-message codes (18/19/34/35/64) remain fatal. See Telegram's
  [service-message rules](https://core.telegram.org/mtproto/service_messages_about_messages).
- **Explicit pings.** ``MTProtoClientConnection/ping()`` retains its `ping_id`
  across salt, clock, sequence and new-session recovery, while tracking each new
  outbound `msg_id`. Its original `requestTimeout` deadline is never extended by
  resends; a pong, timeout, or disconnect completes the waiter only once.
  Keepalive pings, acknowledgements, salt refreshes and graceful session teardown
  have no waiting caller; their existing best-effort/periodic behavior remains.
- **Transport errors.** Server error frames such as `-404` (unknown auth key)
  reach callers as ``MTProtoClientError/protocolError(_:)``, even when the frame
  decoder reports them through the channel's error path.
- **Acknowledgements.** Received messages are acknowledged in batched `msgs_ack`
  rather than one at a time.
- **Liveness.** ``MTProtoClientConfiguration/pingInterval`` drives
  `ping_delay_disconnect`, which both keeps an idle connection alive and lets the
  server drop it promptly if the client vanishes.

## Testing without a socket

Every rule above is enforced by a value or a state machine, not by the channel
handler: ``MTProtoClientHandshake`` takes message bodies and returns message
bodies, ``MTProtoClientSessionCrypto`` takes whole payloads, and
``MTProtoClientConnection`` consumes raw payloads and writes through a sink it is
given. Anything protocol-visible is therefore reachable from a test — or drivable
against a peer over loopback — without opening a connection to a real data
center.
