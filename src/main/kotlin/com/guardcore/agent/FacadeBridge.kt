package com.guardcore.agent

import com.guardcore.core.events.AgentTelemetryMember
import com.guardcore.protocols.AgentHandlerProtocol
import com.guardcore.protocols.RedisHandlerProtocol
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The telemetry sink bridge: the JVM edition of the Rust GuardAgentTelemetry trait pattern. This
 * adapter implements the guard-core facade's [AgentHandlerProtocol] (com.guardcore.protocols, the
 * port of guard_core/protocols/agent_protocol.py) over the standalone [GuardAgent], so the facade's
 * composite handler hands every middleware event and metric - each carrying the full 17-key
 * SecurityEvent envelope (guard_agent models.py:208 shapes) - straight into the agent's
 * at-least-once buffer.
 *
 * Wiring (mirrors the Go engine's AgentHandlerFunc adapter, which restores pluggability between the
 * engine's context-free interface and the agent's context-carrying API):
 * ```kotlin
 * val agent = GuardAgent.create(agentConfig)
 * agent.start()
 * val telemetry = GuardAgentTelemetry(agent)
 * val composite = CompositeAgentHandler(listOf(telemetry))
 * // SecurityEventBus / handlers then receive `composite` as their sink.
 * ```
 *
 * The facade contract is "must not block or raise": every entry point dispatches to the IO
 * dispatcher and swallows agent errors (they are already logged and counted by the agent itself).
 * Redis persistence is configured through [AgentConfig.redis] on the agent, not through the
 * engine's handler, so [initializeRedis] is a documented no-op exactly like the Go adapter's
 * missing per-child surfaces.
 */
public class GuardAgentTelemetry(
    private val agent: GuardAgent,
) : AgentHandlerProtocol, AgentTelemetryMember {
  /** Python async `initialize_redis` (agent_protocol.py:18). No-op: see class KDoc. */
  override suspend fun initializeRedis(redisHandler: RedisHandlerProtocol) {}

  /** The composite member shape (composite_handler.py): same dispatch. */
  override suspend fun sendEvent(event: Map<String, Any?>) {
    sendEvent(event as Any?)
  }

  /** The composite member shape (composite_handler.py): same dispatch. */
  override suspend fun sendMetric(metric: Map<String, Any?>) {
    sendMetric(metric as Any?)
  }

  /** The composite member shape: the redis handler rides in untyped. */
  override suspend fun initializeRedis(redisHandler: Any?) {}

  /** Python async `send_event` (agent_protocol.py:21). Must not block or raise. */
  override suspend fun sendEvent(event: Any?) {
    val map = event as? Map<*, *> ?: return
    val ev = securityEventFromEnvelope(map)
    withContext(Dispatchers.IO) {
      try {
        agent.sendEvent(AgentContext.NONE, ev)
      } catch (ignored: Throwable) {
        // Fail-open by contract: the agent has already logged and counted.
      }
    }
  }

  /** Python async `send_metric` (agent_protocol.py:24). Must not block or raise. */
  override suspend fun sendMetric(metric: Any?) {
    val map = metric as? Map<*, *> ?: return
    val m = securityMetricFromEnvelope(map)
    withContext(Dispatchers.IO) {
      try {
        agent.sendMetric(AgentContext.NONE, m)
      } catch (ignored: Throwable) {
        // Fail-open by contract.
      }
    }
  }

  /** Python async `start` (agent_protocol.py:27). */
  override suspend fun start() {
    withContext(Dispatchers.IO) {
      try {
        agent.start()
      } catch (ignored: Throwable) {}
    }
  }

  /** Python async `stop` (agent_protocol.py:30). Idempotent. */
  override suspend fun stop() {
    withContext(Dispatchers.IO) {
      try {
        agent.stop()
      } catch (ignored: Throwable) {}
    }
  }

  /** Python async `flush_buffer` (agent_protocol.py:33). */
  override suspend fun flushBuffer() {
    withContext(Dispatchers.IO) {
      try {
        agent.flush()
      } catch (ignored: Throwable) {}
    }
  }

  /** Python async `get_dynamic_rules` (agent_protocol.py:36). */
  override suspend fun getDynamicRules(): Any? =
      withContext(Dispatchers.IO) {
        try {
          agent.getDynamicRules()
        } catch (err: Throwable) {
          null
        }
      }

  /** Python async `health_check` (agent_protocol.py:39). */
  override suspend fun healthCheck(): Boolean =
      withContext(Dispatchers.IO) {
        try {
          agent.healthy()
        } catch (err: Throwable) {
          false
        }
      }

  public companion object {
    /**
     * Maps one 17-key SecurityEvent envelope (the emitter output shape of guard-core's
     * securityEventEnvelope, itself the guard_agent models.py:208 constructor) onto the agent wire
     * model. Empty strings pass through: the agent writers treat empty like absent, mirroring
     * omitempty.
     */
    public fun securityEventFromEnvelope(env: Map<*, *>): SecurityEvent {
      val ev = SecurityEvent()
      (env["timestamp"] as? String)?.let { raw ->
        ev.timestamp =
            try {
              java.time.Instant.parse(raw)
            } catch (e: Exception) {
              try {
                java.time.OffsetDateTime.parse(raw).toInstant()
              } catch (e2: Exception) {
                null
              }
            }
      }
      ev.eventType = env["event_type"] as? String ?: ""
      ev.idempotencyKey = env["idempotency_key"] as? String
      ev.ipAddress = env["ip_address"] as? String
      ev.country = env["country"] as? String
      ev.userAgent = env["user_agent"] as? String
      ev.actionTaken = env["action_taken"] as? String
      ev.reason = env["reason"] as? String
      ev.endpoint = env["endpoint"] as? String
      ev.method = env["method"] as? String
      ev.statusCode = env["status_code"] as? Int
      val responseTime = env["response_time"]
      ev.responseTime =
          when (responseTime) {
            is Double -> responseTime
            is Int -> responseTime.toDouble()
            is Long -> responseTime.toDouble()
            else -> null
          }
      ev.decoratorType = env["decorator_type"] as? String
      ev.ruleType = env["rule_type"] as? String
      ev.patternMatched = env["pattern_matched"] as? String
      ev.handlerName = env["handler_name"] as? String
      @Suppress("UNCHECKED_CAST")
      ev.metadata = env["metadata"] as? Map<String, Any?>
      return ev
    }

    /** Maps one metric envelope onto the agent wire model. */
    public fun securityMetricFromEnvelope(env: Map<*, *>): SecurityMetric {
      val m = SecurityMetric()
      (env["timestamp"] as? String)?.let { raw ->
        m.timestamp =
            try {
              java.time.Instant.parse(raw)
            } catch (e: Exception) {
              try {
                java.time.OffsetDateTime.parse(raw).toInstant()
              } catch (e2: Exception) {
                null
              }
            }
      }
      m.metricType = env["metric_type"] as? String ?: ""
      m.value =
          when (val v = env["value"]) {
            is Double -> v
            is Int -> v.toDouble()
            is Long -> v.toDouble()
            else -> 0.0
          }
      m.endpoint = env["endpoint"] as? String
      @Suppress("UNCHECKED_CAST")
      m.tags = env["tags"] as? Map<String, String>
      return m
    }
  }
}
