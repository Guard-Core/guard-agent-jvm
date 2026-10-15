package com.guardcore.agent

import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `agent_test.go`: units, overflow policies, flush triggers, the
 * at-least-once handshake, 413 splitting, rejections, 429/5xx retry, gzip + signatures, the circuit
 * breaker, degraded + health status, and lifecycle guards.
 */
class AgentTest {
  // ------------------------------------------------------------------ help --

  private fun waitUntil(timeout: Duration, msg: String, cond: () -> Boolean) {
    val deadline = System.nanoTime() + timeout.toNanos()
    while (System.nanoTime() < deadline) {
      if (cond()) return
      Thread.sleep(5)
    }
    error("condition not met within $timeout: $msg")
  }

  /** The panic-injection transport seam (agent_test.go panicRoundTripper). */
  private class PanicHttpDoer : HttpDoer {
    override fun execute(
        request: HttpRequest,
        body: ByteArray,
        ctx: AgentContext,
    ): HttpResponse<ByteArray> {
      throw IllegalStateException("transport panic")
    }
  }

  // ---------------------------------------------------------------- units --

  @Test
  fun sendEventRoundTrip() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-rt")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.sendEvent(SecurityEvent(null, "penetration_attempt", ipAddress = "203.0.113.9"))
      agent.flush()
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(1, calls.size, "event calls")
      val call = calls[0]
      assertEquals(1, call.events.size)
      assertEquals("penetration_attempt", call.events[0].eventType)
      assertEquals("test-api-key-123", call.header("X-API-Key"))
      assertTrue(call.header("X-Agent-Install-Id").isNotEmpty(), "X-Agent-Install-Id must be sent")
      assertEquals(userAgent(), call.header("User-Agent"))
      assertTrue(call.batchId.isNotEmpty(), "batch_id must be present")
      assertFalse(call.compressed, "small bodies must not be compressed")
      val stats = agent.stats()
      assertEquals(1L, stats.eventsSent)
      assertEquals(0, stats.eventsPending)
      assertEquals(1L, stats.eventsBuffered)
      assertEquals(AgentStatusValues.HEALTHY, agent.status().state)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun sendMetricRoundTrip() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-metric-rt")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.sendMetric(testMetric(42))
      agent.flush()
      val calls = mock.callsTo(METRICS_PATH)
      assertEquals(1, calls.size)
      assertEquals(1, calls[0].metrics.size)
      assertEquals(42.0, calls[0].metrics[0].value)
      assertEquals(1L, agent.stats().metricsSent)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun sendEventDefaults() {
    val tmp = tempDirFor("agent-defaults")
    val agent = newTestAgent(tmp, null)
    try {
      val before = Instant.now()
      val ev = SecurityEvent(null, "x")
      agent.sendEvent(ev)
      var buffered: SecurityEvent? = null
      synchronized(agent.mutex) { buffered = agent.events.firstOrNull()?.ev }
      assertEquals(1, agent.stats().eventsPending)
      val got = buffered!!
      assertFalse(got.timestamp!!.isBefore(before), "zero timestamp must default to now")
      assertTrue(
          uuid4Pattern.matches(got.idempotencyKey ?: ""),
          "empty idempotency key must default to a uuid",
      )
    } finally {
      agent.stop()
    }
  }

  private val uuid4Pattern =
      Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

  @Test
  fun sendItemValidationErrors() {
    val tmp = tempDirFor("agent-invalid")
    val agent = newTestAgent(tmp, null)
    try {
      var err = assertFailsWith<GuardAgentException> { agent.sendEvent(SecurityEvent()) }
      assertEquals(ErrorKind.INVALID_EVENT, err.errorKind)
      err = assertFailsWith<GuardAgentException> { agent.sendMetric(SecurityMetric(null, "bogus")) }
      assertEquals(ErrorKind.INVALID_EVENT, err.errorKind)
    } finally {
      agent.stop()
    }
  }

  @Test
  fun disabledKinds() {
    val tmp = tempDirFor("agent-disabled")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.enableEvents = false
          c.enableMetrics = false
        }
    try {
      agent.sendEvent(testEvent(1))
      agent.sendMetric(testMetric(1))
      assertEquals(0, agent.stats().eventsPending, "disabled kinds must not buffer")
      assertEquals(0, agent.stats().metricsPending)
    } finally {
      agent.stop()
    }
  }

  // ------------------------------------------------------------- overflow --

  @Test
  fun overflowDropEvictsOldest() {
    val tmp = tempDirFor("agent-drop")
    val agent = newTestAgent(tmp, null) { c -> c.bufferSize = 2 }
    try {
      for (i in 1..4) agent.sendEvent(testEvent(i))
      val stats = agent.stats()
      assertEquals(2L, stats.eventsDropped, "stats $stats")
      assertEquals(2, stats.eventsPending)
      val first: String
      val second: String
      synchronized(agent.mutex) {
        first = agent.events[0].ev.eventType
        second = agent.events[1].ev.eventType
      }
      assertEquals("event_3", first, "oldest must be evicted")
      assertEquals("event_4", second)
    } finally {
      agent.stop()
    }
  }

  @Test
  fun overflowRaise() {
    val tmp = tempDirFor("agent-raise")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.bufferSize = 1
          c.overflow = OverflowPolicy.RAISE
        }
    try {
      agent.sendEvent(testEvent(1))
      val err = assertFailsWith<BufferFullError> { agent.sendEvent(testEvent(2)) }
      assertEquals(ErrorKind.BUFFER_FULL, err.errorKind)
      assertEquals("event", err.kind)
      assertEquals(1, err.maxLen)
    } finally {
      agent.stop()
    }
  }

  @Test
  fun overflowBlockFreesOnFlush() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-block")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 1
          c.overflow = OverflowPolicy.BLOCK
        }
    try {
      agent.sendEvent(testEvent(1))
      val done = Thread {
        agent.sendEvent(AgentContext.NONE, testEvent(2))
      }
      done.start()
      // First flush frees the slot; the blocked sender then buffers event 2.
      agent.flush()
      done.join(5000)
      assertFalse(done.isAlive, "blocked sender must return")
      waitUntil(Duration.ofSeconds(2), "blocked sender must buffer after space frees") {
        agent.stats().eventsPending == 1
      }
      agent.flush()
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(2, calls.size)
      assertEquals("event_1", calls[0].events[0].eventType)
      assertEquals("event_2", calls[1].events[0].eventType)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun overflowBlockRespectsContext() {
    val tmp = tempDirFor("agent-block-ctx")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.bufferSize = 1
          c.overflow = OverflowPolicy.BLOCK
        }
    try {
      agent.sendEvent(testEvent(1))
      val ctx = AgentContext.withTimeout(100)
      val err = assertFailsWith<ContextDone> { agent.sendEvent(ctx, testEvent(2)) }
      assertEquals("context deadline exceeded", err.message)
    } finally {
      agent.stop()
    }
  }

  // ------------------------------------------------------- flush triggers --

  @Test
  fun watermarkEarlyFlush() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-watermark")
    val agent = newTestAgent(tmp, mock) { c -> c.bufferSize = 4 }
    try {
      agent.start()
      // Combined occupancy reaches 4 >= 4 * 0.8 on the fourth enqueue,
      // which must flush without an explicit flush call.
      for (i in 1..4) agent.sendEvent(testEvent(i))
      waitUntil(Duration.ofSeconds(2), "watermark must trigger an early flush") {
        val calls = mock.callsTo(EVENTS_PATH)
        calls.size == 1 && calls[0].events.size == 4
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun dropLogInterval() {
    val logger = CapturingLogger()
    val tmp = tempDirFor("agent-droplog")
    val agent = newTestAgent(tmp, null, AgentOptions().withLogger(logger)) { c -> c.bufferSize = 1 }
    try {
      for (i in 1..103) agent.sendEvent(testEvent(i))
      // 102 drops total; warnings land on the 1st and 101st.
      assertEquals(2, logger.count("total drop(s)"), "drop log lines; log: ${logger.output()}")
    } finally {
      agent.stop()
    }
  }

  // ------------------------------------------------------------- handshake --

  @Test
  fun requeueOrderPreserved() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-requeue")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(5)
        }
    try {
      for (i in 1..3) agent.sendEvent(testEvent(i))
      mock.failNext(1)
      val err = agent.flush()
      assertTrue(err != null, "first flush must fail with a 500 and no retries")
      var stats = agent.stats()
      assertEquals(3L, stats.eventsFailed, "stats after failure: $stats")
      assertEquals(3, stats.eventsPending)
      Thread.sleep(20) // let the 5ms gate expire
      assertEquals(null, agent.flush(), "second flush")
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(2, calls.size)
      for ((i, want) in listOf("event_1", "event_2", "event_3").withIndex()) {
        assertEquals(want, calls[1].events[i].eventType, "requeued order position $i")
      }
      assertEquals(3L, agent.stats().eventsSent)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun requeueTailEvictionUnderPressure() {
    val tmp = tempDirFor("agent-tailevict")
    val agent = newTestAgent(tmp, null) { c -> c.bufferSize = 3 }
    try {
      // The buffer already holds e0; requeueing four items pushes the
      // merged queue to five and evicts from the tail (newest) to capacity.
      agent.sendEvent(testEvent(0))
      val items = (1..4).map { GuardAgent.BufferedEvent(testEvent(it), "") }
      agent.requeueEvents(items)
      val stats = agent.stats()
      assertEquals(2L, stats.eventsDropped, "stats $stats")
      assertEquals(3, stats.eventsPending)
      val order = synchronized(agent.mutex) { agent.events.map { it.ev.eventType } }
      assertEquals("event_1,event_2,event_3", order.joinToString(","), "front of the queue")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun partialFailureRequeues() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-partial")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(5)
        }
    try {
      agent.sendEvent(testEvent(1))
      mock.respondPartialOnce()
      val err = agent.flush()
      assertTrue(err != null, "a 200 with success:false must surface as a flush error")
      assertEquals(1, agent.stats().eventsPending, "partial failure must requeue")
      Thread.sleep(20) // let the 5ms gate expire
      assertEquals(null, agent.flush(), "retry flush")
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(2, calls.size)
      assertEquals("event_1", calls[1].events[0].eventType, "requeued batch must be redelivered")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ------------------------------------------------------------------ 413 --

  @Test
  fun four13SplitsBatch() {
    val mock = MockIngest()
    mock.setMaxBody(1400)
    val tmp = tempDirFor("agent-413-split")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      val pad = "x".repeat(200)
      for (i in 1..4) agent.sendEvent(testEvent(i, pad))
      assertEquals(null, agent.flush())
      var oversized = 0
      var delivered = 0
      for (c in mock.callsTo(EVENTS_PATH)) {
        if (c.response == 413) {
          oversized++
          continue
        }
        delivered += c.events.size
      }
      assertEquals(1, oversized, "413 calls")
      assertEquals(4, delivered, "delivered events")
      assertEquals(0L, agent.stats().eventsDropped, "split must not drop")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun four13SingletonDropped() {
    val mock = MockIngest()
    mock.setMaxBody(1024)
    val tmp = tempDirFor("agent-413-single")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      agent.sendEvent(testEvent(1, "x".repeat(1200)))
      assertEquals(null, agent.flush())
      val stats = agent.stats()
      assertEquals(1L, stats.eventsSent, "singleton 413 must settle durably: $stats")
      assertEquals(0, stats.eventsPending)
      assertEquals(0L, stats.eventsDropped)
      val before = mock.callCount()
      assertEquals(null, agent.flush(), "second flush")
      assertEquals(before, mock.callCount(), "dropped singleton must never be requeued")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ----------------------------------------------------------- rejections --

  @Test
  fun permanentRejectionNotRequeued() {
    val mock = MockIngest()
    mock.reject400Next(10)
    val tmp = tempDirFor("agent-perm")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      for (i in 1..2) agent.sendEvent(testEvent(i))
      assertEquals(null, agent.flush(), "flush with 400 must settle without error")
      val stats = agent.stats()
      assertEquals(2L, stats.eventsSent, "permanent rejection counts as settled: $stats")
      assertEquals(0, stats.eventsPending)
      assertTrue(
          agent.status().errors.joinToString(";").contains("permanently rejected"),
          "status errors must record the rejection: ${agent.status().errors}",
      )
      val before = mock.callCount()
      assertEquals(null, agent.flush(), "second flush")
      assertEquals(before, mock.callCount(), "permanently rejected batches must never be requeued")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // --------------------------------------------------------------- 429/5xx --

  @Test
  fun four29RetryAfterHonored() {
    val mock = MockIngest()
    mock.rateLimitNext(1, "0")
    val tmp = tempDirFor("agent-429")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush())
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(2, calls.size, "expected a 429 then a 200")
      assertEquals(429, calls[0].response)
      assertEquals(1L, agent.stats().eventsSent)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun four29ExhaustedRequeuesBehindGate() {
    val mock = MockIngest()
    mock.rateLimitNext(1, "0")
    val tmp = tempDirFor("agent-429-gate")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(5)
        }
    try {
      agent.sendEvent(testEvent(1))
      val err = agent.flush()
      assertTrue(err is RateLimitedError, "got $err want RateLimitedError")
      assertEquals(1, mock.callCount())
      // The per-kind gate (flush_interval * 2^0 = 5ms) suppresses immediate retries.
      assertEquals(null, agent.flush(), "gated flush must be a no-op")
      assertEquals(1, mock.callCount(), "gated flush must not hit the server")
      Thread.sleep(20)
      assertEquals(null, agent.flush(), "post-gate flush")
      assertEquals(2, mock.callCount())
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun fiveXXRetriedThenAccepted() {
    val mock = MockIngest()
    mock.failNext(2)
    val tmp = tempDirFor("agent-5xx")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 3 }
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush())
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(3, calls.size, "expected two 500s then a 200")
      assertEquals(1L, agent.stats().eventsSent)
      assertEquals(0L, agent.stats().eventsFailed)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun batchIDStableAcrossRetries() {
    val mock = MockIngest()
    mock.failNext(1)
    val tmp = tempDirFor("agent-batchid")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 1 }
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush())
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(2, calls.size)
      assertTrue(calls[0].batchId.isNotEmpty(), "batch id must be present")
      assertEquals(calls[0].batchId, calls[1].batchId, "retries must reuse the batch id")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ------------------------------------------------------------ gzip + sig --

  @Test
  fun gzipAndUncompressedSignature() {
    val mock = MockIngest()
    mock.requireSignatures("test-secret")
    val tmp = tempDirFor("agent-gzip")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.signingSecret = "test-secret"
          c.compressionThreshold = 1
        }
    try {
      agent.sendEvent(testEvent(1, "x".repeat(100)))
      agent.sendEvent(testEvent(2, "y".repeat(100)))
      assertEquals(null, agent.flush())
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(1, calls.size, "event calls")
      val call = calls[0]
      assertTrue(call.compressed, "body must travel gzipped above the threshold")
      assertEquals("gzip", call.header("Content-Encoding"))
      // The server verifies AFTER decompression, so the signature must
      // cover the uncompressed body.
      val sig = call.header(SIGNATURE_HEADER)
      assertTrue(
          verifyPayloadSignature(call.body, sig, "test-secret"),
          "signature $sig must verify over the uncompressed body",
      )
      assertTrue(sig.startsWith("v1="), "signature must carry the v1= prefix")
      assertEquals(2, call.events.size, "decompressed body must contain both events")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun noSignatureHeaderWithoutSecret() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-nosig")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush())
      assertEquals("", mock.callsTo(EVENTS_PATH)[0].header(SIGNATURE_HEADER))
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ------------------------------------------------------- circuit breaker --

  @Test
  fun breakerOpensAndHalfOpenRecovers() {
    val mock = MockIngest()
    mock.failNext(100)
    val tmp = tempDirFor("agent-breaker")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(1)
        }
    try {
      // The per-kind streak gate can swallow individual flush calls, so
      // every phase below polls instead of assuming a given call
      // reaches the server.
      var deadline = System.nanoTime() + 2_000_000_000L
      while (!agent.tr.breaker.open() && System.nanoTime() < deadline) {
        agent.sendEvent(testEvent(1))
        agent.flush()
        Thread.sleep(5)
      }
      assertTrue(agent.tr.breaker.open(), "breaker must open after repeated failures")
      val s = agent.status()
      assertEquals(
          AgentStatusValues.DEGRADED,
          s.state,
          "status must be degraded with an open breaker",
      )
      assertEquals("OPEN", s.circuitState)
      var sawCircuitOpen = false
      deadline = System.nanoTime() + 2_000_000_000L
      while (!sawCircuitOpen && System.nanoTime() < deadline) {
        val err = agent.flush()
        if (err != null && err.matchesKind(ErrorKind.CIRCUIT_OPEN)) sawCircuitOpen = true
        Thread.sleep(5)
      }
      assertTrue(
          sawCircuitOpen,
          "a flush past the gate must surface ErrCircuitOpen while the breaker is open",
      )
      // Advance past the recovery window; the probe call is admitted
      // and a success closes the breaker.
      agent.tr.breaker.now = { Instant.now().plus(BREAKER_RECOVERY_TIMEOUT.multipliedBy(2)) }
      mock.clearKnobs()
      deadline = System.nanoTime() + 2_000_000_000L
      while (System.nanoTime() < deadline) {
        agent.flush()
        val status = agent.status()
        if (status.circuitState == "CLOSED" && agent.stats().eventsSent > 0) {
          return
        }
        Thread.sleep(5)
      }
      error("recovery must close the breaker and deliver telemetry: ${agent.status()}")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun permanentRejectionExemptFromBreaker() {
    val mock = MockIngest()
    mock.reject400Next(100)
    val tmp = tempDirFor("agent-breaker-exempt")
    val agent = newTestAgent(tmp, mock) { c -> c.retryAttempts = 0 }
    try {
      for (i in 1..6) {
        agent.sendEvent(testEvent(i))
        assertEquals(null, agent.flush(), "flush $i")
      }
      assertEquals(
          "CLOSED",
          agent.status().circuitState,
          "permanent rejections must not trip the breaker",
      )
      assertEquals(6, mock.callsTo(EVENTS_PATH).size)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ----------------------------------------------------- degraded + health --

  @Test
  fun degradedStatusAndHealth() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-degraded")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 10
          c.highWatermarkRatio = 1.0
        }
    try {
      assertFalse(agent.healthy(), "agent must be unhealthy before start")
      agent.start()
      // Nine of ten items: degraded by the 90% rule, still healthy by
      // the 95% health rule. No flush triggers because the watermark is 1.0.
      for (i in 1..9) agent.sendEvent(testEvent(i))
      assertEquals(AgentStatusValues.DEGRADED, agent.status().state, "state at 90% occupancy")
      assertTrue(agent.healthy(), "agent at 90% occupancy must still be healthy")
      agent.sendEvent(testEvent(10))
      waitUntil(Duration.ofSeconds(2), "watermark flush must drain the buffer") {
        agent.stats().eventsPending == 0
      }
      assertEquals(AgentStatusValues.HEALTHY, agent.status().state, "state after drain")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun unhealthyWhenFullAndFailing() {
    val tmp = tempDirFor("agent-unhealthy")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.bufferSize = 10
          c.highWatermarkRatio = 1.0
          c.endpoint = "http://127.0.0.1:1"
          c.retryAttempts = 0
        }
    try {
      agent.start()
      for (i in 1..10) agent.sendEvent(testEvent(i))
      waitUntil(Duration.ofSeconds(2), "failed flush must be counted") {
        agent.stats().eventsFailed == 10L
      }
      assertFalse(agent.healthy(), "a full, failing buffer must fail the health check")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun statusReportPayload() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-statusreport")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 10
          c.highWatermarkRatio = 1.0
        }
    try {
      agent.start()
      agent.reportStatus(AgentContext.NONE)
      var calls = mock.callsTo(STATUS_PATH)
      assertEquals(1, calls.size)
      assertEquals(AgentStatusValues.HEALTHY, calls[0].status?.status)
      assertEquals(1L, agent.stats().statusReportsSent)
      // Nine of ten buffered items cross the 90% degraded threshold
      // while the watermark (1.0) still prevents an early flush.
      for (i in 1..9) agent.sendEvent(testEvent(i))
      agent.reportStatus(AgentContext.NONE)
      calls = mock.callsTo(STATUS_PATH)
      assertEquals(AgentStatusValues.DEGRADED, calls.last().status?.status)
      assertEquals(2L, agent.stats().statusReportsSent, "degraded reports still count as sent")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ------------------------------------------------------------- lifecycle --

  @Test
  fun flushBeforeStart() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-flush-prestart")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush(), "flush before start")
      assertEquals(
          1,
          mock.callsTo(EVENTS_PATH).size,
          "buffering and flushing must work before start",
      )
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun stopFinalFlushAndClosedGuards() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-stop")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.start()
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.stop(), "stop")
      assertEquals(1, mock.callsTo(EVENTS_PATH).size, "stop must attempt a final forced flush")
      var err = assertFailsWith<GuardAgentException> { agent.sendEvent(testEvent(2)) }
      assertEquals(ErrorKind.CLOSED, err.errorKind)
      err = assertFailsWith<GuardAgentException> { agent.flush() }
      assertEquals(ErrorKind.CLOSED, err.errorKind)
      err = assertFailsWith<GuardAgentException> { agent.start() }
      assertEquals(ErrorKind.CLOSED, err.errorKind)
      assertEquals(null, agent.stop(), "second stop must be a no-op")
      assertEquals(AgentStatusValues.FAILED, agent.status().state, "status after stop")
    } finally {
      mock.close()
    }
  }

  @Test
  fun startIsIdempotent() {
    val tmp = tempDirFor("agent-start-twice")
    val agent = newTestAgent(tmp, null)
    try {
      agent.start()
      agent.start()
    } finally {
      agent.stop()
    }
  }

  @Test
  fun panicIsolation() {
    val mock = MockIngest()
    val tmp = tempDirFor("agent-panic")
    val agent = newTestAgent(tmp, mock, AgentOptions().withHttpClient(PanicHttpDoer()))
    try {
      agent.sendEvent(testEvent(1))
      val err = agent.flush()
      assertTrue(err != null && err.matchesKind(ErrorKind.INTERNAL), "got $err want ErrInternal")
      // The drained batch must have been requeued by the panic recovery.
      assertEquals(1, agent.stats().eventsPending, "panic must not lose the batch")
      // The agent stays usable.
      agent.sendEvent(testEvent(2))
      agent.stats()
      agent.status()
      agent.healthy()
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun endpointDownIsolation() {
    val tmp = tempDirFor("agent-down")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.endpoint = "http://127.0.0.1:1" // closed port
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(1)
        }
    try {
      agent.sendEvent(
          testEvent(1),
      )
      val err = agent.flush()
      assertTrue(err != null, "flush against a down endpoint must report an error")
      val stats = agent.stats()
      assertEquals(1L, stats.eventsFailed, "failures must be counted: $stats")
      assertTrue(stats.requestsFailed >= 1)
      assertEquals(AgentStatusValues.DEGRADED, agent.status().state, "state after a failure")
      // The agent keeps accepting telemetry despite the dead endpoint.
      agent.sendEvent(testEvent(2))
    } finally {
      agent.stop()
    }
  }

  // ------------------------------------------------------------ flush gate --

  @Test
  fun gateSuppressesImmediateRetries() {
    val mock = MockIngest()
    mock.failNext(1)
    val tmp = tempDirFor("agent-gate")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.flushInterval = Duration.ofMillis(50)
        }
    try {
      agent.sendEvent(testEvent(1))
      val err = agent.flush()
      assertTrue(err != null, "first flush must fail")
      assertEquals(null, agent.flush(), "gated flush must be a silent no-op")
      assertEquals(1, mock.callCount(), "gated flush must not hit the server")
      Thread.sleep(60)
      assertEquals(null, agent.flush(), "post-gate flush")
      assertEquals(2, mock.callCount())
    } finally {
      agent.stop()
      mock.close()
    }
  }
}
