package com.guardcore.agent

import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `parity_test.go`: dynamic rules fetch/cache/fallback, the error hook
 * stages, and the remaining surface pins.
 */
class ParityTest {
  /** parity_test.go `rulesBody`. */
  private fun rulesBody(mutate: ((MutableMap<String, Any?>) -> Unit)? = null): String {
    val raw =
        linkedMapOf<String, Any?>(
            "rule_id" to "rule-42",
            "version" to 7L,
            "ttl" to 300L,
            "ip_blacklist" to listOf("10.0.0.1"),
            "ip_whitelist" to listOf("192.168.1.1"),
            "ip_ban_duration" to 60L,
            "blocked_countries" to listOf("XX"),
            "whitelist_countries" to listOf("YY"),
            "endpoint_rate_limits" to linkedMapOf<String, Any?>("/api/login" to listOf(5L, 60L)),
            "blocked_cloud_providers" to listOf("AWS"),
            "blocked_user_agents" to listOf("badbot"),
            "suspicious_patterns" to listOf("union select"),
            "enable_ip_banning" to true,
            "auto_ban_threshold" to 3L,
            "emergency_mode" to true,
            "emergency_whitelist" to listOf("127.0.0.1"),
            "message" to "lockdown",
        )
    mutate?.invoke(raw)
    return goJson(raw).toString(Charsets.UTF_8)
  }

  @Test
  fun sendRateLimitedByLocalLimiter() {
    // The production limiter is 100/60s; the test swaps in the same
    // limiter type with a tiny window so the denial path stays fast.
    val mock = MockIngest()
    val tmp = tempDirFor("parity-limiter")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      agent.tr.limiter = RateLimiter(2, Duration.ofMillis(100))
      var sendErr: Throwable? = null
      for (i in 1..3) {
        agent.sendEvent(testEvent(i))
        agent.flush()?.let { sendErr = it }
      }
      assertTrue(sendErr != null, "the third flush must fail under the local rate limiter")
      assertTrue(
          sendErr!!.message!!.contains("local rate limit"),
          "unexpected flush error: $sendErr",
      )
      assertEquals(2L, agent.stats().requestsSent)
      assertEquals(2, mock.allCalls().size, "denied attempts must not hit the wire")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ---------------------------------------------------------- dynamic rules --

  @Test
  fun getDynamicRulesFetchesAndCaches() {
    val mock = MockIngest()
    mock.serveRules(200, rulesBody())
    val tmp = tempDirFor("parity-rules")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      val rules = agent.getDynamicRules()
      assertNotNull(rules, "rules must be returned")
      assertEquals("rule-42", rules.ruleId)
      assertEquals(7, rules.version)
      assertTrue(rules.emergencyMode)
      assertEquals("lockdown", rules.message)
      val rl = rules.endpointRateLimits["/api/login"]
      assertTrue(
          rl != null && rl[0] == 5 && rl[1] == 60,
          "endpoint rate limits: ${rules.endpointRateLimits}",
      )
      assertEquals(1L, agent.stats().rulesFetched)

      // Inside the TTL the cache serves without another request.
      assertEquals(rules, agent.getDynamicRules(), "cached rules must be returned within the TTL")
      assertEquals(1, mock.callsTo(RULES_PATH).size, "rules requests")

      // Once the served TTL has elapsed the next call re-fetches (time
      // is advanced by rewinding the last-update stamp).
      synchronized(agent.mutex) {
        agent.rulesLastUpdate = agent.rulesLastUpdate.minus(Duration.ofMinutes(10))
      }
      mock.serveRules(200, rulesBody())
      assertNotNull(agent.getDynamicRules(), "rules must be returned after ttl expiry")
      assertEquals(2, mock.callsTo(RULES_PATH).size)
      assertEquals(2L, agent.stats().rulesFetched)

      // The GET carries the same auth headers as the POST paths.
      val call = mock.callsTo(RULES_PATH)[0]
      assertEquals(
          "test-api-key-123",
          call.header("X-API-Key"),
          "rules request must carry the API key",
      )
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun getDynamicRulesSparsePayloadGetsPythonDefaults() {
    val mock = MockIngest()
    mock.serveRules(200, "{\"emergency_mode\":false}")
    val tmp = tempDirFor("parity-rules-sparse")
    val agent = newTestAgent(tmp, mock)
    try {
      val rules = agent.getDynamicRules()
      assertNotNull(rules, "rules must be returned")
      assertEquals(DEFAULT_RULE_ID, rules.ruleId)
      assertEquals(DEFAULT_RULE_VERSION, rules.version)
      assertEquals(DEFAULT_RULE_TTL_SECONDS, rules.ttl)
      assertEquals(DEFAULT_IP_BAN_DURATION, rules.ipBanDuration)
      assertTrue(rules.ipBlacklist.isEmpty(), "ip_blacklist must decode to an empty list")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun getDynamicRulesFailureServesCache() {
    val mock = MockIngest()
    mock.serveRules(200, rulesBody())
    val tmp = tempDirFor("parity-rules-fail")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      val first = agent.getDynamicRules()
      assertNotNull(first, "first fetch must succeed")

      mock.serveRules(500, "{}")
      val second = agent.getDynamicRules()
      assertEquals(first, second, "a failed fetch must serve the cached rules")
      assertEquals(1L, agent.stats().rulesFetched)

      // No cache and a failing server: null rules, no throw.
      val tmp2 = tempDirFor("parity-rules-fail2")
      val fresh = newTestAgent(tmp2, mock) { c -> c.retryAttempts = 0 }
      try {
        assertNull(fresh.getDynamicRules(), "no-cache failure must return null")
      } finally {
        fresh.stop()
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun getDynamicRulesStartsRulesLoop() {
    val mock = MockIngest()
    mock.serveRules(200, rulesBody())
    val tmp = tempDirFor("parity-rules-loop")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.start()
      waitUntil(Duration.ofSeconds(2), "the rules loop must populate the cache") {
        agent.getDynamicRules() != null
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun dynamicRulesWireRoundTrip() {
    val payload =
        """{
            "rule_id": "r1", "version": 2,
            "timestamp": "2026-09-27T00:00:00Z",
            "expires_at": "2026-09-30T12:00:00Z",
            "ttl": 120,
            "ip_blacklist": ["1.1.1.1"], "ip_whitelist": [], "ip_ban_duration": 30,
            "blocked_countries": ["RU"], "whitelist_countries": ["US"],
            "global_rate_limit": 100, "global_rate_window": 60,
            "endpoint_rate_limits": {"/x": [10, 30]},
            "blocked_cloud_providers": ["GCP"],
            "blocked_user_agents": ["curl"],
            "suspicious_patterns": ["../"],
            "enable_penetration_detection": false,
            "emergency_whitelist_only": true
        }"""
    val rules = DynamicRules.fromJson(payload.toByteArray())
    assertEquals(
        java.time.Instant.parse("2026-09-30T12:00:00Z"),
        rules.expiresAt,
        "expires_at",
    )
    assertEquals(100, rules.globalRateLimit)
    assertEquals(false, rules.enablePenetrationDetection, "must decode false, not the default nil")
    assertTrue(rules.emergencyWhitelistOnly)
    assertTrue(rules.emergencyWhitelist.isEmpty())

    // Re-serialization must emit lists, never null, mirroring pydantic's
    // default_factory=list fields.
    val sb = StringBuilder()
    writeDynamicRulesJson(sb, rules)
    val generic = parseJson(sb.toString(), useNumber = false) as Map<*, *>
    for (key in
        listOf("ip_whitelist", "blocked_countries", "suspicious_patterns", "emergency_whitelist")) {
      assertTrue(generic[key] is List<*>, "$key must serialize as a list, got ${generic[key]}")
    }
  }

  // ------------------------------------------------------------ error hook --

  @Test
  fun onErrorFiresOnPermanentRejection() {
    val mock = MockIngest()
    val hookCalls =
        java.util.concurrent.LinkedBlockingQueue<Triple<String, Throwable?, Map<String, Any?>>>()
    val tmp = tempDirFor("parity-hook-perm")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.onError = OnErrorHook { stage, err, context ->
            hookCalls.add(Triple(stage, err, context))
          }
        }
    try {
      mock.reject400Next(1)
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush(), "permanent rejection must settle without a flush error")
      val call = hookCalls.poll(1, java.util.concurrent.TimeUnit.SECONDS)
      assertNotNull(
          call,
          "on_error must fire with the transport_send stage on a permanent rejection",
      )
      assertEquals(ErrorHookStages.TRANSPORT_SEND, call.first)
      assertEquals("events", call.third["data_type"])
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun onErrorFiresOnFlushFailure() {
    val hookCalls = java.util.concurrent.LinkedBlockingQueue<Pair<String, Throwable?>>()
    val tmp = tempDirFor("parity-hook-flush")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.retryAttempts = 0
          c.endpoint = "http://127.0.0.1:1" // dead port
          c.onError = OnErrorHook { stage, err, _ -> hookCalls.add(Pair(stage, err)) }
        }
    try {
      agent.sendEvent(testEvent(1))
      val err = agent.flush()
      assertTrue(err != null, "flush against a dead endpoint must fail")
      // The baseline fires transport_send at the transport give-up AND
      // flush_events at the flush cycle; drain until the flush stage lands.
      val deadline = System.nanoTime() + 2_000_000_000L
      while (System.nanoTime() < deadline) {
        val call = hookCalls.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS) ?: continue
        if (call.first == ErrorHookStages.FLUSH_EVENTS) {
          assertTrue(call.second != null, "hook must receive the flush error")
          return
        }
      }
      error("on_error must fire with the flush_events stage")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun onErrorPanicsAreContained() {
    val mock = MockIngest()
    val tmp = tempDirFor("parity-hook-panic")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.onError = OnErrorHook { _, _, _ -> throw IllegalStateException("hook boom") }
        }
    try {
      mock.reject400Next(1)
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush(), "a throwing hook must not turn into a flush error")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun onErrorFiresOn413Singleton() {
    val mock = MockIngest()
    mock.setMaxBody(1)
    val stages = java.util.concurrent.LinkedBlockingQueue<String>()
    val tmp = tempDirFor("parity-hook-413")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.onError = OnErrorHook { stage, _, _ -> stages.add(stage) }
        }
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush(), "413 singleton drop must settle")
      val stage = stages.poll(1, java.util.concurrent.TimeUnit.SECONDS)
      assertEquals(
          ErrorHookStages.TRANSPORT_SEND,
          stage,
          "on_error must fire when a singleton still exceeds the limit",
      )
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun encryptionStageConstantMatchesBaseline() {
    // The stage wiring contract (names must match the Python agent exactly).
    assertEquals("encryption", ErrorHookStages.ENCRYPTION)
    assertEquals("transport_send", ErrorHookStages.TRANSPORT_SEND)
    assertEquals("flush_events", ErrorHookStages.FLUSH_EVENTS)
    assertEquals("flush_metrics", ErrorHookStages.FLUSH_METRICS)
  }

  // ------------------------------------------------------------------ LOW --

  @Test
  fun knownEventTypesTable() {
    assertEquals(39, KnownEventTypes.size, "got ${KnownEventTypes.size} known event types want 39")
    for (name in
        listOf(
            "user_agent_blocked",
            "decorator_violation",
            "security_headers_applied",
            "csp_violation",
            "dynamic_rule_violation",
        )) {
      assertTrue(isKnownEventType(name), "$name must be a known event type")
    }
    assertFalse(isKnownEventType("not_a_real_event"), "unknown event types must not match")
    // Documentation, not validation: sendEvent still accepts any type.
    val mock = MockIngest()
    val tmp = tempDirFor("parity-known-events")
    val agent = newTestAgent(tmp, mock)
    try {
      val ev = testEvent(1)
      ev.eventType = "brand_new_engine_event"
      agent.sendEvent(ev)
    } finally {
      agent.stop()
      mock.close()
    }
  }
}
