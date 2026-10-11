package com.guardcore.agent

import com.guardcore.core.events.CompositeAgentHandler
import com.guardcore.protocols.AgentHandlerProtocol
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The sink-bridge suite: GuardAgentTelemetry implements the facade's AgentHandlerProtocol sink
 * (com.guardcore.protocols) so the composite handler hands every middleware event and metric to the
 * agent (the Rust GuardAgentTelemetry trait pattern, Kotlin edition).
 */
class FacadeBridgeTest {
  /** The 17-key envelope shape the guard-core facade emitters build. */
  private fun envelope(
      eventType: String,
      metadata: Map<String, Any?> = emptyMap(),
  ): Map<String, Any?> =
      linkedMapOf(
          "idempotency_key" to newUUID4(),
          "timestamp" to Instant.now().toString(),
          "event_type" to eventType,
          "ip_address" to "203.0.113.7",
          "country" to null,
          "user_agent" to null,
          "action_taken" to "BLOCKED",
          "reason" to "penetration attempt detected",
          "endpoint" to "/login",
          "method" to "POST",
          "status_code" to null,
          "response_time" to null,
          "decorator_type" to null,
          "rule_type" to null,
          "pattern_matched" to null,
          "handler_name" to "middleware",
          "metadata" to metadata,
      )

  @Test
  fun bridgeImplementsFacadeProtocol() {
    val tmp = tempDirFor("bridge-protocol")
    val agent = newTestAgent(tmp, null)
    val bridge: AgentHandlerProtocol = GuardAgentTelemetry(agent)
    try {
      // Every protocol entry point is reachable and never raises.
      runBlocking { bridge.start() }
      runBlocking { bridge.sendEvent(envelope("penetration_attempt")) }
      runBlocking {
        bridge.sendMetric(
            linkedMapOf(
                "timestamp" to Instant.now().toString(),
                "metric_type" to MetricTypes.REQUEST_COUNT,
                "value" to 1.0,
            ),
        )
      }
      runBlocking { bridge.flushBuffer() }
      // healthCheck mirrors agent.healthy(): false before start.
      assertFalse(runBlocking { bridge.healthCheck() }, "an unstarted agent fails the health check")
      assertNull(runBlocking { bridge.getDynamicRules() }, "no rules fetched: null rules")
    } finally {
      runBlocking { bridge.stop() }
      agent.stop()
    }
  }

  @Test
  fun bridgeDeliversEnvelopeThroughTheAgent() {
    val mock = MockIngest()
    val tmp = tempDirFor("bridge-deliver")
    val agent = newTestAgent(tmp, mock)
    val bridge = GuardAgentTelemetry(agent)
    try {
      runBlocking { bridge.sendEvent(envelope("suspicious_request")) }
      assertEquals(1, agent.stats().eventsPending, "the envelope must land in the agent buffer")
      agent.flush()
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(1, calls.size)
      val delivered = calls[0].events[0]
      assertEquals("suspicious_request", delivered.eventType)
      assertEquals("203.0.113.7", delivered.ipAddress)
      assertEquals("BLOCKED", delivered.actionTaken)
      assertEquals("/login", delivered.endpoint)
      assertEquals("POST", delivered.method)
      assertNotNull(delivered.idempotencyKey, "the envelope idempotency key must ride along")
    } finally {
      runBlocking { bridge.stop() }
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun bridgeMapsEveryEnvelopeField() {
    val env =
        envelope(
                "rate_limited",
                metadata = linkedMapOf("retry_after" to 30),
            )
            .toMutableMap()
    env["status_code"] = 429
    env["response_time"] = 12.5
    env["country"] = "US"
    val ev = GuardAgentTelemetry.securityEventFromEnvelope(env)
    assertEquals("rate_limited", ev.eventType)
    assertEquals(429, ev.statusCode)
    assertEquals(12.5, ev.responseTime)
    assertEquals("US", ev.country)
    assertEquals("middleware", ev.handlerName)
    assertEquals(30, (ev.metadata?.get("retry_after") as? Int))
    assertTrue(ev.timestamp != null, "the envelope timestamp must parse")
  }

  @Test
  fun bridgeSwallowsAgentErrors() {
    val tmp = tempDirFor("bridge-swallow")
    val agent = newTestAgent(tmp, null)
    val bridge = GuardAgentTelemetry(agent)
    try {
      agent.stop()
      // A closed agent throws ErrClosed; the bridge must swallow it.
      runBlocking { bridge.sendEvent(envelope("ip_banned")) }
      runBlocking { bridge.sendMetric(linkedMapOf("metric_type" to "bogus")) }
      runBlocking { bridge.flushBuffer() }
      assertFalse(runBlocking { bridge.healthCheck() }, "a closed agent fails the health check")
    } finally {
      runBlocking { bridge.stop() }
      agent.stop()
    }
  }

  @Test
  fun bridgePlugsIntoTheCompositeHandler() {
    val mock = MockIngest()
    val tmp = tempDirFor("bridge-composite")
    val agent = newTestAgent(tmp, mock)
    val bridge = GuardAgentTelemetry(agent)
    val composite = CompositeAgentHandler(listOf(bridge))
    try {
      runBlocking {
        composite.start()
        composite.sendEvent(envelope("penetration_attempt"))
        composite.sendMetric(
            linkedMapOf(
                "timestamp" to Instant.now().toString(),
                "metric_type" to MetricTypes.THREAT_LEVEL,
                "value" to 3.0,
            ),
        )
        composite.flushBuffer()
      }
      assertEquals(1, mock.callsTo(EVENTS_PATH).size, "the composite must fan out to the agent")
      assertEquals(1, mock.callsTo(METRICS_PATH).size)
    } finally {
      runBlocking { composite.stop() }
      agent.stop()
      mock.close()
    }
  }
}
