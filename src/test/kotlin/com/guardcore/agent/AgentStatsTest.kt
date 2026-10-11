package com.guardcore.agent

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `agentstats_test.go`: the reference get_stats dict view (guard_agent
 * _client_status.py get_stats) the engine's middleware agent_stats merge consumes.
 */
class AgentStatsTest {
  @Test
  fun agentStatsDictShape() {
    val tmp = tempDirFor("stats-shape")
    val agent = newTestAgent(tmp, null)
    try {
      val stats = agent.agentStats()
      // An unstarted agent: running=false, uptime=0, no cached rules,
      // and the zero rules_last_update renders as null (the reference None).
      assertEquals(false, stats["running"])
      assertEquals(0.0, stats["uptime"])
      assertEquals(false, stats["cached_rules"])
      assertEquals(null, stats["rules_last_update"])
      for (key in
          listOf(
              "events_sent",
              "metrics_sent",
              "events_failed",
              "metrics_failed",
              "rules_fetched",
          )) {
        assertNotNull(stats[key], "the dict must carry \"$key\"")
      }
      val buffer = stats["buffer_stats"] as Map<*, *>
      for (key in
          listOf(
              "events_buffered",
              "metrics_buffered",
              "events_flushed",
              "metrics_flushed",
              "events_dropped",
              "metrics_dropped",
              "current_event_buffer_size",
              "current_metric_buffer_size",
              "redis_persist_failures",
              "durability_degraded",
          )) {
        assertNotNull(buffer[key], "buffer_stats must carry \"$key\"")
      }
      val transport = stats["transport_stats"] as Map<*, *>
      for (key in listOf("requests_sent", "requests_failed", "circuit_breaker_state")) {
        assertNotNull(transport[key], "transport_stats must carry \"$key\"")
      }
    } finally {
      agent.stop()
    }
  }

  @Test
  fun agentStatsDictRunningArms() {
    val tmp = tempDirFor("stats-arms")
    val agent = newTestAgent(tmp, null)
    try {
      synchronized(agent.mutex) {
        agent.started = true
        agent.startedAt = Instant.now().minusSeconds(2)
        agent.cachedRules = DynamicRules()
        agent.rulesLastUpdate = Instant.now()
      }
      agent.stop()

      // After stop the agent reports running=false again, but the
      // uptime and rule-state arms carried values while started:
      // recompute against a fresh started window to pin both arms.
      synchronized(agent.mutex) {
        agent.closed = false
        agent.started = true
      }
      val stats = agent.agentStats()
      val uptime = stats["uptime"] as Double
      assertTrue(uptime >= 2.0, "a started agent must report its uptime, got $uptime")
      assertEquals(
          true,
          stats["cached_rules"],
          "a fetched rules snapshot must report cached_rules=true",
      )
      val last = stats["rules_last_update"] as? String
      assertTrue(!last.isNullOrEmpty(), "a stamped rules update must render the timestamp")
    } finally {
      agent.stop()
    }
  }
}
