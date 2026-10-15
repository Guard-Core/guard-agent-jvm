<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>JVM telemetry agent for the [Guard ecosystem](https://github.com/Guard-Core/guard-core). Buffers security events, metrics, and agent status locally and ships them to the Guard Core App ingestion API with at-least-once delivery: nothing acknowledged is lost, nothing unacknowledged is forgotten.</strong>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/code-ql.yml">
        <img src="https://github.com/Guard-Core/guard-agent-jvm/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
</p>

___

## Status

`3.2.4`: the agent is a TRUE PORT of [guard-agent-go](https://github.com/Guard-Core/guard-agent-go) v3.2.2 (~3.8k non-test LOC), behavior 1:1 with byte-exact observable surfaces (wire payloads, header names, event/metric model shapes, config keys, AES-GCM and HMAC parameters pinned against the Go test vectors). Released on Maven Central as `com.guard-core:guard-agent-jvm:3.2.4`. The 3.2.4 line mirrors the guard-agent 3.2.4 release (version reporting lockstep with the engines at guard-core 4.3.3).

## What this is

- Per-kind queues (events, metrics) with size and time flush triggers and a high-watermark early flush.
- Overflow policies: `drop` (default), `block`, `raise`.
- At-least-once handshake: drain, send, then confirm or requeue in the original order.
- gzip request bodies and an HMAC-SHA256 `v1=` signature that covers the **uncompressed** body, which is what the server verifies after decompression.
- Retry with exponential backoff, `Retry-After` honoring (capped at 300s), 413 recursive split-or-drop, 400/404/422 permanent rejection, 200-partial requeue, per-kind failure-streak backoff, and a 5-failure / 60s circuit breaker.
- Optional Redis persistence (Lettuce): write-on-enqueue with a TTL, delete-on-confirm, reload on `start`, fail-open on any Redis error.
- AES-256-GCM payload encryption for the `/api/v1/events/encrypted` ingest path, byte-compatible with the Python agent (canonical JSON plaintext, 12-byte nonce prefix, 16-byte GCM tag, padded urlsafe base64), fail-closed at construction (no plaintext fallback).
- Redaction at capture and again at serialization; stable install identity persisted to `~/.guard-agent/install-id`; SaaS dynamic rules with a TTL cache and a background poll loop; a best-effort `onError` hook (`transport_send`, `encryption`, `flush_events`, `flush_metrics`).
- Failure isolation: no exported method throws an unexpected exception or blocks the host beyond the configured overflow policy.

## Install

Published on Maven Central:

```kotlin
dependencies {
    implementation("com.guard-core:guard-agent-jvm:3.2.4")
}
```

To build from source instead:

```sh
git clone https://github.com/Guard-Core/guard-core-jvm.git ../guard-core-jvm   # engine, pinned ref 2415a77
git clone https://github.com/Guard-Core/guard-agent-jvm.git
cd guard-agent-jvm && ./gradlew build
```

Set `GUARD_CORE_USE_COMPOSITE=false` to build without the composite: the declared engine coordinates then resolve from the repositories (mavenLocal first, then Maven Central) - this is how the release workflow proves the published artifact graph (docs/release.md).

## Usage

```kotlin
import com.guardcore.agent.*

fun main() {
    val cfg = defaultConfig()
    cfg.apiKey = "your-ingest-api-key"
    cfg.projectId = "your-project-id"
    // cfg.endpoint = "https://your-guard-core-app.example.com"

    val agent = GuardAgent.create(cfg)
    agent.start()

    agent.sendEvent(
        SecurityEvent(
            timestamp = null,
            eventType = "penetration_attempt",
            ipAddress = "203.0.113.7",
            method = "GET",
            endpoint = "/admin",
            reason = "suspicious pattern",
        ),
    )
    agent.sendMetric(SecurityMetric(timestamp = null, metricType = MetricTypes.REQUEST_COUNT, value = 1.0))

    // ...

    agent.stop() // cancels the loops, then one final forced flush
}
```

Redis durability is one field away and never makes the agent depend on Redis being up:

```kotlin
cfg.redis = RedisConfig(url = "redis://localhost:6379")
cfg.signingSecret = System.getenv("INGEST_PAYLOAD_SIGNING_SECRET")
cfg.projectEncryptionKey = System.getenv("GUARD_PROJECT_ENCRYPTION_KEY") // enables /api/v1/events/encrypted
```

### Wiring the guard-core facade sink (AgentProtocol)

The JVM engine's emitters carry the full 17-key SecurityEvent envelope (guard_agent models.py:208 shapes). `GuardAgentTelemetry` implements the facade's `AgentHandlerProtocol` sink **and** the composite handler's member shape, so the engine hands every middleware event and metric straight into the at-least-once buffer (the Rust `GuardAgentTelemetry` trait pattern, Kotlin edition):

```kotlin
import com.guardcore.agent.GuardAgentTelemetry
import com.guardcore.core.events.CompositeAgentHandler

val agent = GuardAgent.create(agentConfig)
agent.start()

val telemetry = GuardAgentTelemetry(agent)
val composite = CompositeAgentHandler(listOf(telemetry))
// SecurityEventBus / the handlers then receive `composite` as their sink.
```

Every bridge entry point dispatches to the IO dispatcher and swallows agent errors (the facade contract is "must not block or raise"); the agent has already logged and counted them. Redis persistence is configured through `AgentConfig.redis` on the agent itself, so `initializeRedis` is a documented no-op, exactly like the Go engine's `AgentHandlerFunc` adapter that bridges the engine's context-free interface to the agent's context-carrying API.

## Reliability semantics

| Situation | Behavior |
| --- | --- |
| Buffer full, `drop` (default) | Evict the oldest item of that kind, confirm its persisted record, log every 100th drop |
| Buffer full, `block` | Wait for a flush to free space (throws the context error if the context ends first) |
| Buffer full, `raise` | `sendEvent`/`sendMetric` throw `BufferFullError` (`matchesKind(ErrorKind.BUFFER_FULL)`) |
| Flush trigger | Combined occupancy at or above `bufferSize * highWatermarkRatio`, or `flushInterval` elapsed |
| 200 | Confirm: delete persisted records, reset the failure streak |
| 200 with `success:false` or `errors[]` | Requeue the whole batch in original order (at-least-once: duplicates possible, losses are not) |
| 429 | Honor `Retry-After` (60s default, 300s cap) and retry |
| 413 | Halve the batch and send both halves; a singleton that still 413s is dropped durably (encrypted batches cannot split, so a 413 drops durably) |
| 400 / 404 / 422 | Permanent: drop durably, never requeue |
| 401 / 403 / 5xx / network | Retry with `backoffFactor * 2^attempt` (60s cap) |
| Repeated per-kind failure | Gate that kind for `min(flushInterval * 2^(streak-1), 300s)` |
| 5 consecutive transport failures | Circuit breaker opens for 60s, then admits one probe (half-open); permanent rejections and 413s are exempt |
| `status()` | `healthy`, `degraded` (breaker open, 90% occupancy, or >10% lifetime failure rate), or `failed` after `stop` |
| Redis unavailable | Log, count, keep going; writes pause for 30s after 3 consecutive failures; records expire by TTL |
| `stop` | Cancel the loops, then one final flush that bypasses the backoff gates |

### The signature covers the uncompressed body

The ingestion API verifies `X-Payload-Signature` **after** its gzip middleware decompresses the request (`telemetry_router.py`, `payload_signature.py`), so the signature must be an HMAC-SHA256 over the uncompressed JSON. This agent signs before compression and sends `v1=<hex>` accordingly, exactly like guard-agent-go and unlike the Python/TypeScript agents (whose signatures stop verifying under gzip).

### Dynamic rules

`getDynamicRules(ctx)` fetches the SaaS rule document from `GET /api/v1/rules` (the full Python-agent `DynamicRules` surface, sparse payloads default-filled like `DynamicRules(**response_data)`) and caches it for the document's `ttl`; a failed poll serves the last known rules. `start` runs a background polling loop on `dynamicRuleInterval`, and `stats().rulesFetched` counts refreshes. `truncatePayload`, `hashIP`, and `KnownEventTypes` round out the host-adapter helper surface.

## Configuration

Start from `defaultConfig()` and override. `retryAttempts` and `compressionThreshold` are zero-honest (0 means zero retries, and 0 compresses every body); the feature booleans are false in a hand-built `AgentConfig()`.

| Field | Default | Notes |
| --- | --- | --- |
| `apiKey` | required | At least 10 characters |
| `endpoint` | `https://api.guard-core.com` | Trailing `/` and `/api/v1` are stripped |
| `projectId` | empty | Sent as `X-Project-Id` |
| `bufferSize` | 100 | Per-kind capacity |
| `flushInterval` | 30s | Flush cadence and backoff base |
| `statusInterval` | 300s | Minimum 60s |
| `dynamicRuleInterval` | 300s | Dynamic rules polling cadence, minimum 60s |
| `highWatermarkRatio` | 0.8 | Early flush threshold |
| `maxConcurrentFlushes` | 1 | Wake-driven flushers |
| `overflow` | `drop` | `drop`, `block`, `raise` |
| `retryAttempts` | 3 via `defaultConfig()` | 0 disables retries |
| `timeout` | 30s | Per request |
| `backoffFactor` | 1.0 | Seconds, base of `2^attempt` |
| `compressionEnabled` / `compressionThreshold` | true / 1024 | gzip at or above the threshold |
| `signingSecret` | empty | Enables `X-Payload-Signature` |
| `projectEncryptionKey` | empty | urlsafe-base64 AES-256 key; enables the encrypted ingest path, fail-closed |
| `sensitiveHeaders` | defaults | Header names redacted from event metadata and metric tags (case-insensitive); null = defaults, non-null replaces |
| `maxPayloadSize` | 1024 | Payload size (bytes) to truncate at with `truncatePayload` before embedding in event metadata |
| `onError` | null | Best-effort failure callback `(stage, err, context)`; stages: `transport_send`, `encryption`, `flush_events`, `flush_metrics` |
| `installId` / `installIdPath` | auto / `~/.guard-agent/install-id` | Override either |
| `redis` | null | `url`, `prefix` (`guard:agent`), `ttl` (1h) |
| `guardVersion` / `guardCoreVersion` | empty | Reported to the API |

## Development

```sh
./gradlew build          # detekt + ktfmt check + the full test suite
./gradlew test           # tests only
```

The Redis-backed persistence tests PING `REDIS_HOST` (default `127.0.0.1:6379`) and skip themselves when it is unreachable; CI runs a `redis:7-alpine` container and checks out the engine at the pinned ref. The engine dependency (`com.guard-core:guard-core:4.3.3`, groupId com.guard-core, the Central Portal namespace) is compile-only and lives behind a composite-build substitution (`settings.gradle.kts`), mirroring guard-agent-go whose library core is engine-free.

## Links

- [guard-core](https://github.com/Guard-Core/guard-core): the Python engine that anchors the ecosystem.
- [guard-core-jvm](https://github.com/Guard-Core/guard-core-jvm): the JVM engine + facade this agent plugs into.
- [guard-agent](https://github.com/Guard-Core/guard-agent) / [guard-agent-go](https://github.com/Guard-Core/guard-agent-go): Python and Go sibling agents (the port reference).
- [guard-core-app](https://github.com/Guard-Core/guard-core-app): hosts the ingestion API.
- [spring-boot-guard](https://github.com/Guard-Core/spring-boot-guard) / [ktor-guard](https://github.com/Guard-Core/ktor-guard): JVM adapters that emit the events.

## License

MIT
