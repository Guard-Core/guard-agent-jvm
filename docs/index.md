# guard-agent-jvm

JVM telemetry agent for the [Guard ecosystem](https://github.com/Guard-Core/guard-core).
Buffers security events, metrics, and agent status locally and ships them to
the Guard Core App ingestion API with at-least-once delivery: nothing
acknowledged is lost, nothing unacknowledged is forgotten.

- **Status**: 3.2.3, released; a TRUE PORT of
  [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) v3.2.2
  (behavior 1:1 with byte-exact observable surfaces: wire payloads, header
  names, event/metric model shapes, config keys, AES-GCM and HMAC parameters
  pinned against the Go test vectors). The 3.2.3 line mirrors the
  guard-agent 3.2.3 release (lockstep with the engines at 4.3.3)
- **Coordinates**: `com.guard-core:guard-agent-jvm:3.2.3` at release
- **Runtime**: engine-free (compile-only facade contract over
  `com.guardcore.protocols`)

## Documentation map

- [Installation](installation.md) - coordinates, engine composite, Redis option
- [API](api.md) - configuration, lifecycle, the facade sink bridge
