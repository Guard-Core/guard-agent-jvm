# Changelog

All notable changes to guard-agent-jvm are documented here. The version line mirrors guard-agent 3.2.3 (the family versioning law); releases ship as v-prefixed git tags after the family's W8 certification.

## Unreleased

- The agent now fills `AgentConfig.guardCoreVersion` at construction from the guard-core-jvm engine found on the runtime classpath (read reflectively, so the engine stays an optional dependency) when the config leaves it empty, so Java projects report their engine version like the Go and PHP agents. A user-set value always wins.

## [3.2.3] - 2026-10-13

### Changed (release train)

- First Maven Central release (`com.guard-core:guard-agent-jvm:3.2.3`), lockstep with guard-agent 3.2.3 and built against guard-core-jvm 4.3.3.
- Dependencies: lettuce-core 6.7.1.RELEASE -> 6.8.2.RELEASE (netty 4.1.125) and slf4j-api 2.0.20, lockfile regenerated; the osv-scanner suppression GHSA-3p8m-j85q-pgmj is removed (fixed in netty 4.1.125).
- Dependency locking ignores the family's own `com.guard-core:*` artifacts. The release publish job resolves the engine from Maven Central instead of the composite build, and those modules were absent from the lock state, so the publish build failed lock validation.
- The pinned guard-core-jvm engine ref moves to the 4.3.3 release commit.

### Changed (W10, the 3.2.3 sync; nothing released)

- Version reporting lockstep: the agent moves to 3.2.3, mirroring the guard-agent 3.2.3 release and the engines at guard-core 4.3.3 (the family versioning law). `AGENT_VERSION`, the project version, the README/docs surfaces, and the engine pin (`guardCore` 4.3.3) move together.
- Tamper-test fidelity: the encryption tamper test now flips the last encrypted byte (inside the GCM tag) via `last ^ 0xFF` instead of appending a byte, so the rejection always exercises authenticated decryption and can never pass on a length check (ports the guard-agent 3.2.3 `test_decrypt_tampered_payload` improvement).

### Changed (W8b, release engineering; nothing released)

- Maven coordinates move to groupId `com.guard-core` (the Central Portal namespace; guardcore.com
  proved unverifiable and is not owned by the operator; nothing was ever published under
  `com.guardcore`). Kotlin/JVM packages stay `com.guardcore.*` (hyphens are illegal in JVM
  packages).
- `maven-publish` + `signing` with sources/javadoc jars and the Portal-required POM (MIT license,
  developers, scm); repositories move to `settings.gradle.kts`; `GUARD_CORE_USE_COMPOSITE` env
  toggle (default composite ON; `false` = resolve the engine from mavenLocal, then Maven Central,
  the release-workflow mode). The published POM carries no guard-core dependency (compileOnly):
  the agent artifact stays engine-free at runtime.
- `.github/workflows/release.yml`: engine-artifact pre-flight on Maven Central (engine before
  adapters and agent), tests at tag, tag-consistency audit (bare vX.Y.z, tag equals the in-file
  version, SNAPSHOT flip enforced), publish job with per-artifact repo1 existence check and a
  Central Portal deployment. See docs/release.md.

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
