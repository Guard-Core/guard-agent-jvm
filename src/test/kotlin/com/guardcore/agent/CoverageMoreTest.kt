package com.guardcore.agent

import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `coverage_more_test.go`: the transport, dynamic-rules, and agent branches
 * that need targeted seams or crafted inputs. Redis-backed durability branches live in the
 * integration tier.
 */
class CoverageMoreTest {
  private fun transport(
      mock: MockIngest?,
      mutate: ((AgentConfig) -> Unit)? = null,
  ): Transport {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    mock?.let { cfg.endpoint = it.url }
    mutate?.invoke(cfg)
    return Transport(cfg, "install", null, quietLogger())
  }

  @Test
  fun payloadTooLargeErrorRenders() {
    val err = PayloadTooLargeError("huge")
    assertEquals("guardagent: payload too large: huge", err.message)
  }

  @Test
  fun canonicalJSONWritesFalseBool() {
    assertEquals("{\"flag\":false}", canonicalJSON(linkedMapOf("flag" to false)))
  }

  @Test
  fun resolveInstallIDFallsBackToDefaultPathAndMemory() {
    // Empty override resolves a fresh id through the default path (the
    // HOME-less memory arm is unreachable in-process on the JVM; recorded
    // in KNOWN_GAPS.md).
    val id = resolveInstallID("", "", quietLogger())
    assertTrue(id.isNotEmpty(), "no override must still yield an id")
  }

  @Test
  fun canonicalItemsJSONDecodeFailure() {
    // Malformed canonical bytes (from the marshal seam) must surface as a
    // decode failure for both kinds.
    val tr = transport(null)
    val saved = tr.jsonMarshal
    try {
      tr.jsonMarshal = { "{not json".toByteArray() }
      assertFailsWith<Exception> { tr.canonicalItemsJSON(listOf(testEvent(1)), null) }
      tr.jsonMarshal = { "[1,".toByteArray() }
      assertFailsWith<Exception> { tr.canonicalItemsJSON(null, listOf(testMetric(1))) }
    } finally {
      tr.jsonMarshal = saved
    }
  }

  @Test
  fun sendEncryptedBatchEnvelopeMarshalFailure() {
    val tr = transport(null)
    tr.encryptor =
        PayloadEncryptor.create(
            // Any valid 32-byte key.
            java.util.Base64.getUrlEncoder().encodeToString(ByteArray(32)),
        )
    val saved = tr.jsonMarshal
    try {
      tr.jsonMarshal = { v ->
        if (v is EncryptedEnvelope) throw java.io.IOException("envelope marshal exploded")
        else goJson(v)
      }
      val (outcome, err) = tr.sendEncryptedBatch(AgentContext.NONE, listOf(testEvent(1)), null)
      assertEquals(SendOutcome.PARTIAL, outcome, "envelope marshal failure must be partial")
      assertTrue(err != null, "envelope marshal failure must carry the error")
    } finally {
      tr.jsonMarshal = saved
    }
  }

  @Test
  fun marshalBatchRemarshalFailure() {
    val tr = transport(null) { c -> c.compressionThreshold = 16 }
    val saved = tr.jsonMarshal
    try {
      var calls = 0
      tr.jsonMarshal = { v ->
        calls++
        if (calls >= 2) throw java.io.IOException("remarshal exploded") else goJson(v)
      }
      val batch = EventBatch()
      batch.projectId = "p"
      batch.events = listOf(testEvent(1, "x".repeat(64)))
      assertFailsWith<Exception> { tr.marshalBatch(batch) }
    } finally {
      tr.jsonMarshal = saved
    }
  }

  @Test
  fun sendBatchLocalLimiterDefersThenSends() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.projectId = "acme"
          c.retryAttempts = 1
        }
    try {
      val limiter = RateLimiter(1, Duration.ofMillis(20))
      tr.limiter = limiter
      limiter.seedCallsForTest(listOf(Instant.now()))
      val (outcome, err) = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray(), true)
      assertEquals(
          SendOutcome.ACCEPTED,
          outcome,
          "a deferred local gate must retry and accept, got $outcome $err",
      )
      assertEquals(null, err)
      assertEquals(
          1,
          mock.callsTo(EVENTS_PATH).size,
          "the deferred attempt must not reach the API twice",
      )
    } finally {
      mock.close()
    }
  }

  @Test
  fun sendMetricsThroughEncryptor() {
    val mock = MockIngest()
    val key = java.util.Base64.getUrlEncoder().encodeToString(ByteArray(32))
    val tr = transport(mock) { c -> c.projectEncryptionKey = key }
    try {
      tr.encryptor = PayloadEncryptor.create(key)
      val (outcome, err) = tr.sendMetrics(AgentContext.NONE, listOf(testMetric(1)))
      assertEquals(
          SendOutcome.ACCEPTED,
          outcome,
          "encrypted metrics must confirm, got $outcome $err",
      )
      assertEquals(null, err)
      assertEquals(
          1,
          mock.callsTo(ENCRYPTED_PATH).size,
          "encrypted metrics must hit the encrypted endpoint",
      )
    } finally {
      mock.close()
    }
  }

  @Test
  fun splitOrDropEventsFailsWhenHalfFails() {
    val mock = MockIngest()
    val tr = transport(mock) { c -> c.retryAttempts = 0 }
    try {
      // Four events: the full batch trips the size guard, both halves
      // fit, and the first half fails so the aggregate reports failure.
      val pad = "x".repeat(40)
      val events = (0..3).map { testEvent(it, pad) }
      mock.setMaxBody(320)
      mock.failNext(2)
      val outcome = tr.splitOrDropEvents(AgentContext.NONE, events)
      assertEquals(SendOutcome.FAILED, outcome, "a failed split half must fail the aggregate")
      mock.clearKnobs()
      mock.setMaxBody(262144)
    } finally {
      mock.close()
    }
  }

  @Test
  fun sendBatchNewRequestFailure() {
    val tr = transport(null)
    tr.cfg.endpoint = "://bad endpoint"
    val (outcome, err) = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray(), true)
    assertEquals(SendOutcome.FAILED, outcome, "an unparseable endpoint must fail the request build")
    assertTrue(err != null, "an unparseable endpoint must fail the request build")
  }

  @Test
  fun sendBatchRetriesAfter429() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 2
          c.backoffFactor = 0.001
        }
    try {
      mock.rateLimitNext(1, "0.05")
      val (outcome, err) = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray(), true)
      assertEquals(
          SendOutcome.ACCEPTED,
          outcome,
          "a 429 followed by a success must accept, got $outcome $err",
      )
      assertEquals(null, err)
      assertEquals(2, mock.callsTo(EVENTS_PATH).size, "the batch must retry once after the 429")
    } finally {
      mock.close()
    }
  }

  @Test
  fun newFailsWhenRoundTripVerificationFails() {
    val saved = cryptoRandRead
    try {
      cryptoRandRead = { throw java.io.IOException("no entropy") }
      val cfg = defaultConfig()
      cfg.apiKey = "test-api-key-123"
      cfg.projectEncryptionKey = java.util.Base64.getUrlEncoder().encodeToString(ByteArray(32))
      cfg.installIdPath = tempDirFor("covmore-rt").resolve("install-id").toString()
      assertFailsWith<EncryptionConfigError> { GuardAgent.create(cfg) }
    } finally {
      cryptoRandRead = saved
    }
  }

  @Test
  fun normalizeRejectsUnparseableRedisURL() {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.redis = RedisConfig("redis://127.0.0.1:6379/\u007f", "p", Duration.ofMinutes(1))
    val err = normalize(cfg).error
    assertTrue(
        err != null && err!!.message!!.contains("redis url must be"),
        "an unparseable redis url must be rejected, got $err",
    )
  }

  @Test
  fun sendMetricAfterStop() {
    val mock = MockIngest()
    val tmp = tempDirFor("covmore-afterstop")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.stop()
      val err = assertFailsWith<GuardAgentException> { agent.sendMetric(testMetric(1)) }
      assertEquals(ErrorKind.CLOSED, err.errorKind, "sendMetric after stop must be ErrClosed")
    } finally {
      mock.close()
    }
  }

  @Test
  fun overflowBlockPollsWhileWaiting() {
    for (kind in listOf("event", "metric")) {
      val mock = MockIngest()
      // The agent is deliberately not started: no flusher runs, so the
      // blocked sender stays parked until the poll fires.
      val tmp = tempDirFor("covmore-poll-$kind")
      val agent =
          newTestAgent(tmp, mock) { c ->
            c.bufferSize = 1
            c.highWatermarkRatio = 1.0
            c.overflow = OverflowPolicy.BLOCK
          }
      try {
        if (kind == "event") {
          agent.sendEvent(testEvent(1))
        } else {
          agent.sendMetric(testMetric(1))
        }
        val canceled = AgentContext.withCancel()
        val done = Thread {
          try {
            if (kind == "event") {
              agent.sendEvent(canceled, testEvent(2))
            } else {
              agent.sendMetric(canceled, testMetric(2))
            }
          } catch (err: Throwable) {
            // The sender surfaces the context error; capture it below.
          }
        }
        done.start()
        // The blocked sender polls (500ms) before the context ends.
        Thread.sleep(700)
        canceled.cancel()
        done.join(5000)
        assertFalse(done.isAlive, "block policy must honor the context after polling")
      } finally {
        agent.stop()
        mock.close()
      }
    }
  }

  @Test
  fun settleMetricsNilErrorAfterFailedSplit() {
    val mock = MockIngest()
    val tmp = tempDirFor("covmore-settle")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      // Four metrics: the full batch trips the size guard, both halves
      // fit, and the first half fails with 500s so the aggregate reports
      // failure with a null error, which settleMetrics must replace
      // before requeueing.
      val pad = "x".repeat(40)
      for (i in 0 until 4) {
        val metric = testMetric(i)
        metric.tags = linkedMapOf("pad" to pad)
        agent.sendMetric(metric)
      }
      mock.setMaxBody(350)
      mock.failNext(2)
      val err = agent.flush()
      assertTrue(err != null, "the failed split must surface a synthetic error")
      assertEquals(4, agent.stats().metricsPending, "the failed split must requeue everything")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun reportStatusRecoversFromPanic() {
    val mock = MockIngest()
    val tmp = tempDirFor("covmore-statuspanic")
    val agent = newTestAgent(tmp, mock, AgentOptions().withHttpClient(AgentTestPanicDoer()))
    try {
      agent.reportStatus(AgentContext.NONE)
      assertEquals(1L, agent.stats().statusReportsFailed, "a status panic must count as failed")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun reserveKeysMarshalFailureCountsAndRecords() {
    val logger = quietLogger()
    // A hand-built agent with a persistence handle whose serialization
    // path fails (the Go poisoned-channel analog: an unserializable value).
    val agent = GuardAgent(AgentConfig(), logger, "install")
    agent.tr = Transport(agent.cfg, "install", null, logger)
    // A non-null (dead) persistence handle puts the reservation path
    // under observation exactly like the Go zero-client persistence.
    val deadPersist = Persistence("redis://127.0.0.1:1", "p", Duration.ofMinutes(1), logger)
    agent.persist = deadPersist
    val poisoned =
        SecurityEvent(null, "e", metadata = linkedMapOf<String, Any?>("chan" to Thread()))
    agent.persistEventNow(GuardAgent.BufferedEvent(poisoned, ""))
    assertEquals(1L, agent.stats().redisPersistFailures, "serialization failures must count")
    agent.persistMetricNow(
        GuardAgent.BufferedMetric(SecurityMetric(null, MetricTypes.REQUEST_COUNT), ""),
    )
    assertEquals(2L, agent.stats().redisPersistFailures, "store failures must count")
    deadPersist.close()
  }

  @Test
  fun flushIfNeededWakesEmptyAndWatermark() {
    val mock = MockIngest()
    val tmp = tempDirFor("covmore-wake")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 2
          c.highWatermarkRatio = 0.5
        }
    try {
      agent.start()
      // A wake with an empty buffer must be a no-op (given time to consume).
      agent.triggerFlush()
      Thread.sleep(50)
      // A single item crosses the 0.5 watermark of a 2-slot buffer: the
      // wake flusher must drain it even though no interval elapsed.
      agent.sendEvent(testEvent(1))
      waitUntil(Duration.ofSeconds(5), "watermark wake must flush") {
        agent.stats().eventsPending == 0 && agent.stats().eventsSent == 1L
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }
}
