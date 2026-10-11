# Changelog

All notable changes to guard-agent-jvm are documented here. The version line mirrors guard-agent 3.2.2 (the family versioning law); releases ship as v-prefixed git tags after the family's W8 certification.

## Unreleased (3.2.2-SNAPSHOT)

### Added

- W7 real port of [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) v3.2.2, behavior 1:1 with byte-exact observable surfaces:
  - Buffering: per-kind queues with size/time triggers, high-watermark early flush, `drop`/`block`/`raise` overflow policies, at-least-once confirm/requeue handshake with front-requeue and tail eviction under pressure (ports `agent.go`).
  - Transport: gzip above the threshold, HMAC-SHA256 `v1=` signature over the UNCOMPRESSED body, retry with exponential backoff, capped `Retry-After` on 429, recursive 413 split-or-drop, 400/404/422 permanent rejection, 200-partial requeue, per-kind failure-streak gates, 5-failure / 60s circuit breaker, local sliding-window rate limiter (ports `transport.go`, `circuit_breaker.go`, `rate_limiter.go`).
  - Crypto: AES-256-GCM payload encryption byte-compatible with the Python agent (canonical JSON plaintext with sorted keys and ensure_ascii escaping, 12-byte nonce prefix, 16-byte GCM tag, padded urlsafe base64), fail-closed construction, and HMAC-SHA256 signing pinned against the Go test vectors (ports `encryption.go`, `signing.go`).
  - Redis persistence via Lettuce: write-on-enqueue with TTL, delete-on-confirm through a serialized confirm worker, scan-and-reload on start (oldest first, corrupt records dropped and deleted, over-capacity eviction), fail-open accounting with a 3-failure / 30s write cooldown (ports `persistence.go`).
  - Models: SecurityEvent / SecurityMetric / batch / status / encrypted-envelope wire shapes, the 39-entry KnownEventTypes table, the 7 accepted metric types, UUID4 and batch-id generators with fail-open entropy fallbacks (ports `models.go`).
  - Config: every field, default, zero-honest field, and validator message from `config.go` (endpoint `/api/v1` stripping with the reference warning, overflow vocabulary validation, redis defaults).
  - Dynamic rules: the full SaaS rule surface with Python-default overlay decoding, TTL cache, background poll loop, and last-known-rules outage fallback (ports `dynamic_rules.go`).
  - Redaction: capture-time and serialization-time passes, case-insensitive trimmed key matching, JSON-string scanning with wholesale fail-closed redaction over depth/size bounds (ports `redact.go`).
  - Install identity: override / persisted state file / in-memory fail-open resolution (ports `install_id.go`).
  - Error hook: `transport_send`, `encryption`, `flush_events`, `flush_metrics` stages with panic containment (ports `error_hook.go`).
- Telemetry sink bridge: `GuardAgentTelemetry` implements the guard-core facade's `AgentHandlerProtocol` sink and the composite handler member shape, so the engine's composite hands every middleware event and metric (the full 17-key SecurityEvent envelope) into the agent buffer; the Rust `GuardAgentTelemetry` trait pattern, Kotlin edition.
- Test surface: 196 JUnit tests ported from the Go test suite (16 files), including the byte-compat proof against the vendored Go encryption vectors (`testdata/encryption_vectors.json`, byte-identical) and the HMAC signing vector; the Redis-backed durability tier runs live against `REDIS_HOST` and skips when unreachable.
- CI: Redis service container and the pinned guard-core-jvm engine checkout (ref `5f4ea56`) behind a composite-build substitution; the engine dependency is compile-only, keeping the artifact transitive-free exactly like the engine-free Go agent library.
