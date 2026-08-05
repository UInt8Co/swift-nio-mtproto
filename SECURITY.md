# Security

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting on this repository (**Security → Report a
vulnerability**), which opens a private advisory visible only to the maintainers.

Useful things to include: the affected module and version, whether the problem is
reachable from a remote peer, and a reproduction — a byte sequence or a failing
test is ideal.

## Scope

This package implements MTProto's transport, handshake and encrypted-message
layers, so the interesting attack surface is what an untrusted peer can send: the
frame decoders, the obfuscation handler, the handshake state machines, the
envelope codec, and the inbound validators. Reports about those, including denial
of service through malformed input, are in scope.

Weaknesses in MTProto itself are out of scope here — this package implements the
protocol as specified and cannot fix its design.
