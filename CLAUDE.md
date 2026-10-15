# AGENTS.md
Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

guard-agent-jvm is the JVM (Kotlin) telemetry agent for the Guard ecosystem. It is a framework-agnostic library (package `com.guardcore.agent`) that buffers security events, metrics, and agent status in memory and ships them to the Guard Core App ingestion API with at-least-once delivery guarantees: nothing acknowledged is lost, nothing unacknowledged is forgotten. It is a port of guard-agent-go, whose behavior is itself pinned to the Python reference agent `guard-agent`.

- **Maven coordinates**: `com.guard-core:guard-agent-jvm` (Kotlin packages stay `com.guardcore.*`)
- **Toolchain**: Kotlin on JDK 17, Gradle wrapper
- **License**: MIT
- **Version**: in `build.gradle.kts` and `Version.kt`, kept in lockstep with the agent family
- **Runtime dependencies**: Lettuce (optional Redis persistence), kotlinx-coroutines; the guard-core-jvm engine is `compileOnly` (the facade sink contract) so the published artifact stays engine-free

## Ecosystem Position

```
guard-core (Python engine) / guard-core-jvm (JVM engine)
├── guard-agent (Python) / guard-agent-go / guard-agent-rs / guard-agent-jvm (this repo)  <- Telemetry agents
└── ktor-guard, spring-boot-guard                                                          <- JVM adapters
```

The agent contains no security-detection logic. Engines and adapters produce events, the agent ships them to the SaaS ingestion API hosted by guard-core-app.

## Architecture

```
src/main/kotlin/com/guardcore/agent/
├── GuardAgent.kt       # Agent: per-kind buffers, flush loops, at-least-once handshake, lifecycle (agent.go)
├── AgentConfig.kt      # AgentConfig, defaultConfig, OverflowPolicy, RedisConfig, normalization (config.go)
├── Models.kt           # SecurityEvent, SecurityMetric, wire payload writers, uuid helpers (models.go)
├── Transport.kt        # HTTP transport: gzip, HMAC signing, retry loop, 429/413/4xx/5xx handling (transport.go)
├── CircuitBreaker.kt   # 5 consecutive failures, 60s recovery, half-open probing (circuit_breaker.go)
├── Persistence.kt      # Optional Redis durability: persist-on-enqueue, TTL, confirm-delete, reload (persistence.go)
├── DynamicRules.kt     # SaaS dynamic rules fetch with the same retry machinery (dynamic_rules.go)
├── Encryption.kt       # AES-256-GCM for /api/v1/events/encrypted (encryption.go)
├── Signing.kt          # HMAC-SHA256 "v1=" signatures over the uncompressed body (signing.go)
├── Redaction.kt        # Sensitive-header redaction at capture and at serialization (redact.go)
├── FacadeBridge.kt     # GuardAgentTelemetry: the guard-core-jvm AgentHandlerProtocol sink
└── ...                 # AgentContext, AgentErrors, AgentUtils, ErrorHook, InstallId, RateLimiter, InternalJson, Version
src/test/kotlin/...     # JUnit tests; MockIngest.kt mocks the ingestion contract
src/test/resources/     # reference-generated vectors (response_vectors.json, wire_shape.json) and their generators
```

Key invariants an agent must preserve when editing:

1. The handshake is always drain, then send, then confirm (delete persisted records) or requeue in the original order; under buffer pressure during requeue the TAIL (newest items) is evicted.
2. The HMAC signature covers the UNCOMPRESSED JSON body even when the wire bytes are gzipped; the server verifies after decompression.
3. No exported method may throw an unexpected exception or block the host beyond the documented overflow policy; telemetry failures are logged and counted.
4. Per-kind state (queues, failure streaks, backoff gates) stays independent: one kind failing must never stall the other.
5. Redis failures are fail-open: log, count, keep going. Redis writes never run on the caller's thread or under the buffer lock, and the writes in flight are capped at `bufferSize`.
6. The Python agent is the baseline. A behavior change starts in the Python reference and guard-agent-go, never here alone.

## Reliability Semantics

| Situation | Behavior |
| --- | --- |
| Buffer full, `drop` (default) | Oldest same-kind item evicted, its Redis record confirmed, drop logged every 100th drop |
| Buffer full, `block` | Sender waits (500ms poll, wake on drain) until space frees or the context ends |
| Buffer full, `raise` | `sendEvent`/`sendMetric` throw `BufferFullError` |
| Flush trigger | Combined occupancy >= `bufferSize * highWatermarkRatio`, or `flushInterval` elapsed |
| 200 success | Confirm: persisted records deleted, counters updated, streak reset |
| 200 with `success:false` or `errors[]` | Partial failure: whole batch requeued in original order; a 200 body without `success` is accepted |
| Unparseable or empty-object 200, 202, 204, 3xx, 405, 408 | Transient no-result: retried at once, never opens the breaker |
| 429 | Honor `Retry-After` (default 60s when absent or invalid, clamped to 300s), then retry |
| 413 | Recursive split-or-drop (encrypted batches are re-encrypted per half); a singleton that still 413s is durably dropped |
| 400 / 404 / 422 | Permanent rejection: batch dropped durably, records confirmed, never requeued, never counted against the breaker |
| 401 / 403 / 5xx / network error | Retried with `backoffFactor * 2^attempt`, capped at 60s |
| Per-kind failure streak | Gate flushes for `min(flushInterval * 2^(streak-1), 300s)`; success resets |
| Circuit breaker | Opens after 5 consecutive transport failures, probes after 60s (`CLOSED`, `OPEN`, `HALF_OPEN`); permanent rejections, 413s and cancelled contexts are exempt |
| Degraded status | Breaker open, combined occupancy >= 90%, or lifetime failure rate > 10% over events plus metrics |
| Redis persistence | Write on enqueue with TTL, delete on confirm, reload on `start`; fail-open with a 30s write cooldown after 3 consecutive failures |
| `stop` | Cancels loops, then one final flush of each kind under its backoff gate |

## Development Commands

| Command | Purpose |
| --- | --- |
| `./gradlew spotlessApply detekt` | Format and lint (CI fails on `spotlessCheck` or detekt findings) |
| `./gradlew build --no-daemon` | Full gate: compile, lint, tests (Redis on 6379 for the persistence tests) |
| `./gradlew test --tests 'com.guardcore.agent.RefParityTest'` | One test class |

The build needs the guard-core-jvm engine checkout as a sibling (`../guard-core-jvm`) or via `GUARD_CORE_JVM_DIR`; `GUARD_CORE_USE_COMPOSITE=0` resolves it from Maven instead. Persistence tests PING `REDIS_HOST` (default `127.0.0.1:6379`) and skip when it is unreachable. Never flush a shared Redis: the tests use their own key prefixes and clean up by prefix.

## Testing Guidelines

- `kotlin.test` on JUnit 5. Timing-sensitive tests poll (`waitUntil`) or gate on latches instead of sleeping, because per-kind backoff gates legitimately swallow flush attempts.
- `MockIngest.kt` implements the ingestion contract (gzip decompression, post-decompression signature verification, 413 at the size limit, partial-failure 200s).
- Response and wire semantics are replayed from vectors generated by the Python agent (`src/test/resources/gen_response_vectors.py`, `gen_wire_shape.py`); regenerate them, never hand-edit.
- New behavior needs a test that would fail without it.

## Best Practices

- Never push to `master` directly and never push `v*` tags; work on feature branches and PRs.
- Conventional commits (`feat:`, `test:`, `docs:`, `ci:`, `fix:`), no AI attribution in commit messages or PR bodies.
- Do not hand-edit the version; it moves in lockstep with the agent family.
- Do not edit `CHANGELOG.md` in a feature PR; release prep writes it.
- Preserve the failure-isolation policy when touching exported methods.
- Documentation edits go to README.md and AGENTS.md; CLAUDE.md must stay byte-identical to AGENTS.md (`cmp AGENTS.md CLAUDE.md`).

## Related Projects

- [guard-core](https://github.com/Guard-Core/guard-core): the framework-agnostic Python engine that anchors the ecosystem.
- [guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm): the JVM engine whose adapters emit the telemetry this agent ships.
- [guard-agent](https://github.com/Guard-Core/guard-agent): the Python reference agent.
- [guard-agent-go](https://github.com/Guard-Core/guard-agent-go): the Go agent this repo ports.
- [guard-core-app](https://github.com/Guard-Core/guard-core-app): hosts the ingestion API this agent reports to.
