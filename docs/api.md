# API

The agent's public surface (package `com.guardcore.agent`).

## Configuration and lifecycle

`AgentConfig` carries the ingestion endpoint, API key, project id, buffer
sizes, flush intervals, overflow policy, and the optional Redis persistence
and encryption settings; `defaultConfig()` gives the reference defaults. The
agent is created and started explicitly:

```kotlin
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

agent.stop() // cancels the loops, then one final flush under the backoff gates
```

Behavioral surface (1:1 with guard-agent-go):

- Per-kind queues (events, metrics) with size and time flush triggers and a
  high-watermark early flush; overflow policies `drop` (default), `block`,
  `raise`.
- At-least-once handshake: drain, send, then confirm or requeue in the
  original order.
- gzip request bodies and an HMAC-SHA256 `v1=` signature covering the
  uncompressed body.
- Retry with exponential backoff, `Retry-After` honoring (capped at 300s),
  413 recursive split-or-drop, 400/404/422 permanent rejection, 200-partial
  requeue, per-kind failure-streak backoff, and a 5-failure / 60s circuit
  breaker.
- Optional Redis persistence (one field away, never a hard dependency):
  `cfg.redis = RedisConfig(url = "redis://localhost:6379")`.
- AES-256-GCM payload encryption for the `/api/v1/events/encrypted` ingest
  path, byte-compatible with the Python agent, fail-closed at construction.
- Redaction at capture and again at serialization; stable install identity in
  `~/.guard-agent/install-id`; SaaS dynamic rules with a TTL cache and a
  background poll loop; the best-effort `onError` hook.
- Failure isolation: no exported method throws an unexpected exception or
  blocks the host beyond the configured overflow policy.

## Wiring the guard-core facade sink

The engine's emitters carry the full 17-key SecurityEvent envelope.
`GuardAgentTelemetry` (the FacadeBridge) implements the facade's
`AgentHandlerProtocol` sink and the composite handler's member shape, so the
engine hands every middleware event and metric straight into the
at-least-once buffer (the Rust `GuardAgentTelemetry` trait pattern, Kotlin
edition):

```kotlin
import com.guardcore.agent.GuardAgentTelemetry
import com.guardcore.core.events.CompositeAgentHandler

val agent = GuardAgent.create(agentConfig)
agent.start()

val telemetry = GuardAgentTelemetry(agent)
val composite = CompositeAgentHandler(listOf(telemetry))
// SecurityEventBus / the handlers then receive `composite` as their sink.
```

Redis persistence is configured through `AgentConfig.redis` on the agent, and
the facade contract ("must not block or raise") holds on every entry point.
