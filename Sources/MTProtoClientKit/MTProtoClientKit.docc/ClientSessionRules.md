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
  out-of-window message cannot be delivered twice.
- **Salts.** `bad_server_salt`, `new_session_created` and `future_salts` all
  carry a salt to adopt; the request that triggered a `bad_server_salt` is
  retried with the corrected one rather than surfaced as a failure.
- **`bad_msg_notification`.** Codes 16, 17 and 18 mean the client's own ids were
  wrong; the connection adjusts and retries.
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
