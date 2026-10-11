package com.guardcore.agent

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Port of guard-agent-go `redact_test.go`. */
class RedactTest {
  // ------------------------------------------------ SanitizeHeaders units --

  @Test
  fun sanitizeHeadersDefaultSensitiveSet() {
    val sensitive = normalizeSensitiveHeaders(null)
    val want = listOf("authorization", "proxy-authorization", "cookie", "x-api-key")
    assertEquals(want, sensitive)
  }

  @Test
  fun sanitizeHeadersRedactsEachDefaultHeader() {
    for (header in listOf("authorization", "proxy-authorization", "cookie", "x-api-key")) {
      val metadata = linkedMapOf<String, Any?>(header to "secret-value", "ok" to "fine")
      val sanitized = sanitizeHeaders(metadata, DEFAULT_SENSITIVE_HEADERS)
      val got = sanitized as? Map<*, *> ?: error("$header: wrong result type")
      assertEquals("[REDACTED]", got[header], "$header value must be redacted")
      assertEquals("fine", got["ok"], "$header: non-sensitive value disturbed")
    }
  }

  @Test
  fun sanitizeHeadersMatchesCaseInsensitiveAndTrimmed() {
    val metadata =
        linkedMapOf<String, Any?>(
            "Authorization" to "bearer x",
            "  COOKIE  " to "session=1",
            "X-API-KEY" to "k",
            "PROXY-AUTH" to "no",
            "Proxy-Authoriz" to "no",
        )
    val got = sanitizeHeaders(metadata, null) as Map<*, *>
    assertEquals("[REDACTED]", got["Authorization"])
    assertEquals("[REDACTED]", got["  COOKIE  "])
    assertEquals("[REDACTED]", got["X-API-KEY"])
    // "PROXY-AUTH" and "Proxy-Authoriz" are NOT in the default set.
    assertEquals("no", got["PROXY-AUTH"])
    assertEquals("no", got["Proxy-Authoriz"])
  }

  @Test
  fun sanitizeHeadersRecursesNestedStructures() {
    val metadata =
        linkedMapOf<String, Any?>(
            "request" to
                linkedMapOf<String, Any?>(
                    "headers" to
                        listOf<Any?>(
                            linkedMapOf<String, Any?>("Cookie" to "session=1"),
                            linkedMapOf<String, Any?>("Accept" to "text/html"),
                        ),
                ),
        )
    val sanitized = sanitizeHeaders(metadata, listOf("cookie"))
    val outer = ((sanitized as Map<*, *>)["request"] as Map<*, *>)
    val headers = outer["headers"] as List<*>
    val first = headers[0] as Map<*, *>
    val second = headers[1] as Map<*, *>
    assertEquals("[REDACTED]", first["Cookie"], "nested cookie value must be redacted")
    assertEquals("text/html", second["Accept"])
  }

  @Test
  fun sanitizeHeadersJSONStringValues() {
    val metadata =
        linkedMapOf<String, Any?>(
            "payload" to "{\"authorization\":\"secret\",\"keep\":1}",
            "notjson" to "{authorization: secret",
            "scalar" to "plain",
        )
    val got = sanitizeHeaders(metadata, null) as Map<*, *>
    val payload = got["payload"] as String
    val parsed = parseJson(payload, useNumber = false) as Map<*, *>
    assertEquals("[REDACTED]", parsed["authorization"], "JSON string scan must redact")
    assertEquals(1.0, parsed["keep"], "JSON string scan must keep non-sensitive fields")
    assertEquals("{authorization: secret", got["notjson"])
    assertEquals("plain", got["scalar"])
  }

  @Test
  fun sanitizeHeadersOversizeJSONStringRedactedWholesale() {
    // A JSON-looking string longer than the 8192-byte scan bound is
    // redacted rather than walked, mirroring the Python agent.
    val big = "{\"a\":\"" + " ".repeat(9000) + "\"}"
    val sanitized = sanitizeHeaders(linkedMapOf("payload" to big), null)
    assertEquals("[REDACTED]", (sanitized as Map<*, *>)["payload"])
  }

  @Test
  fun sanitizeHeadersDepthLimitRedactsWholesale() {
    var deep: Any? = linkedMapOf<String, Any?>("leaf" to "value")
    repeat(15) { deep = linkedMapOf<String, Any?>("nested" to deep) }
    val sanitized = sanitizeHeaders(linkedMapOf("root" to deep), null)
    var got: Any? = (sanitized as Map<*, *>)["root"]
    repeat(10) { got = (got as Map<*, *>)["nested"] }
    assertEquals(
        "[REDACTED]",
        got,
        "subtree deeper than the depth bound was not redacted wholesale",
    )
  }

  @Test
  fun sanitizeHeadersScalarsPassUnknownStructRedacted() {
    val metadata =
        linkedMapOf<String, Any?>(
            "count" to 3,
            "ratio" to 0.5,
            "on" to true,
            "absent" to null,
            "opaque" to Thread(),
        )
    val got = sanitizeHeaders(metadata, null) as Map<*, *>
    assertEquals(3, got["count"])
    assertEquals(0.5, got["ratio"])
    assertEquals(true, got["on"])
    assertEquals(null, got["absent"])
    assertEquals("[REDACTED]", got["opaque"], "unrepresentable values must be redacted fail-closed")
  }

  @Test
  fun sanitizeHeadersDoesNotMutateInput() {
    val metadata = linkedMapOf<String, Any?>("authorization" to "secret")
    sanitizeHeaders(metadata, null)
    assertEquals("secret", metadata["authorization"], "input map mutated")
  }

  // --------------------------------------------------- config surface ------

  @Test
  fun defaultConfigSensitiveHeadersNilMeansDefaults() {
    val cfg = defaultConfig()
    assertEquals(
        null,
        cfg.sensitiveHeaders,
        "DefaultConfig().sensitiveHeaders must stay null (defaults)",
    )
    val tmp = tempDirFor("redact-defaults")
    val agent = newTestAgent(tmp, null)
    try {
      val got = agent.cfg.sensitiveHeaders
      val want = listOf("authorization", "proxy-authorization", "cookie", "x-api-key")
      assertEquals(want, got, "normalized sensitive headers")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun configSensitiveHeadersCaseNormalized() {
    val tmp = tempDirFor("redact-normalize")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.sensitiveHeaders = listOf("  X-Custom-Secret ", "AUTHORIZATION")
        }
    try {
      assertEquals(listOf("x-custom-secret", "authorization"), agent.cfg.sensitiveHeaders)
    } finally {
      agent.stop()
    }
  }

  // -------------------------------------------- public API end-to-end -----

  @Test
  fun sendEventRedactsSensitiveMetadataAtCapture() {
    val mock = MockIngest()
    val tmp = tempDirFor("redact-event")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.sensitiveHeaders = listOf("authorization", "x-custom-secret")
        }
    try {
      val ev =
          SecurityEvent().apply {
            eventType = "penetration_attempt"
            metadata =
                linkedMapOf(
                    "authorization" to "Bearer sk-live",
                    "X-Custom-Secret" to "hunter2",
                    "cookie" to "session=1",
                    "safe" to "value",
                )
          }
      agent.sendEvent(ev)
      agent.flush()
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(1, calls.size)
      assertEquals(1, calls[0].events.size)
      val md = calls[0].events[0].metadata ?: emptyMap()
      assertEquals("[REDACTED]", md["authorization"])
      assertEquals("[REDACTED]", md["X-Custom-Secret"])
      // A custom list replaces the defaults, so cookie is no longer sensitive.
      assertEquals("session=1", md["cookie"])
      assertEquals("value", md["safe"])
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun sendMetricRedactsSensitiveTagsAtCapture() {
    val mock = MockIngest()
    val tmp = tempDirFor("redact-metric")
    val agent = newTestAgent(tmp, mock) { c -> c.sensitiveHeaders = listOf("x-api-key") }
    try {
      val metric =
          SecurityMetric().apply {
            metricType = MetricTypes.REQUEST_COUNT
            value = 1.0
            tags = linkedMapOf("x-api-key" to "k", "route" to "/health")
          }
      agent.sendMetric(metric)
      agent.flush()
      val calls = mock.callsTo(METRICS_PATH)
      assertEquals(1, calls.size)
      assertEquals(1, calls[0].metrics.size)
      val tags = calls[0].metrics[0].tags ?: emptyMap()
      assertEquals("[REDACTED]", tags["x-api-key"])
      assertEquals("/health", tags["route"], "safe tag disturbed")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun defaultSensitiveHeadersApplyWithoutConfig() {
    val mock = MockIngest()
    val tmp = tempDirFor("redact-nocfg")
    val agent = newTestAgent(tmp, mock)
    try {
      val ev =
          SecurityEvent().apply {
            eventType = "ip_banned"
            metadata = linkedMapOf("Cookie" to "a=b", "referer" to "https://x")
          }
      agent.sendEvent(ev)
      agent.flush()
      val md = mock.callsTo(EVENTS_PATH)[0].events[0].metadata ?: emptyMap()
      assertEquals(
          "[REDACTED]",
          md["Cookie"],
          "default set did not redact Cookie case-insensitively",
      )
      assertEquals("https://x", md["referer"])
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun emptyNonNilSensitiveHeadersDisablesRedaction() {
    val mock = MockIngest()
    val tmp = tempDirFor("redact-empty")
    val agent = newTestAgent(tmp, mock) { c -> c.sensitiveHeaders = emptyList() }
    try {
      val ev =
          SecurityEvent().apply {
            eventType = "rate_limited"
            metadata = linkedMapOf("authorization" to "kept-by-request")
          }
      agent.sendEvent(ev)
      agent.flush()
      val md = mock.callsTo(EVENTS_PATH)[0].events[0].metadata ?: emptyMap()
      assertEquals(
          "kept-by-request",
          md["authorization"],
          "explicit empty list did not replace defaults",
      )
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun serializationPassRedactsAgain() {
    // The serialization-time pass must redact even when a caller bypassed
    // the capture-time pass, mirroring the Python transport's second pass.
    val cfg = defaultConfig()
    val tr = Transport(cfg, "install", null, quietLogger())
    val batch = EventBatch()
    batch.events =
        listOf(
            SecurityEvent().apply {
              eventType = "penetration_attempt"
              metadata = linkedMapOf("authorization" to "late-secret", "ok" to 1)
            },
        )
    val raw = tr.marshalBatch(batch)
    val wire = parseJson(raw, useNumber = false) as Map<*, *>
    val events = wire["events"] as List<*>
    val md = (events[0] as Map<*, *>)["metadata"] as Map<*, *>
    assertEquals("[REDACTED]", md["authorization"], "wire body carried unredacted authorization")
    assertEquals(1.0, md["ok"], "safe metadata disturbed on the wire")
    assertTrue(true)
  }
}
