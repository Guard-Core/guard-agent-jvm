package com.guardcore.agent

/**
 * W0 scaffold placeholder for the JVM telemetry agent.
 *
 * The layout mirrors guard-agent-go conceptually. The module map below lands in W7:
 * - buffering: local durable queue with size and time flush triggers
 * - transport: Guard Core App ingestion API client with retry and backoff
 * - circuit breaker: fail-open shipping semantics
 * - Redis persistence: cross-process buffer recovery
 * - encryption: AES-GCM at rest
 * - signing: HMAC request signing
 * - redaction: header and body scrubbing before export
 * - dynamic rules: remote configuration of what ships
 */
object GuardAgent {

  /** Tracks the 3.2.2 artifact line until the first tagged release. */
  const val VERSION: String = "3.2.2"
}
