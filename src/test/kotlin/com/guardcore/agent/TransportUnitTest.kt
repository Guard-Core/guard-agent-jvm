package com.guardcore.agent

import java.time.Duration
import java.util.zip.GZIPInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Port of guard-agent-go `transport_unit_test.go` + transport coverage arms. */
class TransportUnitTest {
  @Test
  fun parseRetryAfter() {
    val cases =
        listOf(
            "" to Duration.ofSeconds(60),
            "   " to Duration.ofSeconds(60),
            "abc" to Duration.ofSeconds(60),
            "0" to Duration.ZERO,
            "30" to Duration.ofSeconds(30),
            "-5" to Duration.ZERO,
            "301" to Duration.ofSeconds(300),
            "2.5" to Duration.ofMillis(2500),
        )
    for ((header, want) in cases) {
      assertEquals(want, parseRetryAfter(header), "parseRetryAfter(\"$header\")")
    }
  }

  @Test
  fun retryBackoff() {
    val cases =
        listOf(
            Triple(0, 1.0, Duration.ofSeconds(1)),
            Triple(1, 1.0, Duration.ofSeconds(2)),
            Triple(2, 1.0, Duration.ofSeconds(4)),
            Triple(3, 0.5, Duration.ofSeconds(4)),
            Triple(10, 1.0, MAX_RETRY_BACKOFF),
        )
    for ((attempt, factor, want) in cases) {
      assertEquals(want, retryBackoff(attempt, factor), "retryBackoff($attempt, $factor)")
    }
  }

  @Test
  fun partialFailureBackoff() {
    val interval = Duration.ofSeconds(1)
    val cases =
        listOf(
            0 to Duration.ofSeconds(1), // clamped to 1
            1 to Duration.ofSeconds(1),
            2 to Duration.ofSeconds(2),
            3 to Duration.ofSeconds(4),
            4 to Duration.ofSeconds(8),
            9 to Duration.ofSeconds(256),
            10 to MAX_PARTIAL_BACKOFF,
            50 to MAX_PARTIAL_BACKOFF,
        )
    for ((streak, want) in cases) {
      assertEquals(want, partialFailureBackoff(streak, interval), "partialFailureBackoff($streak)")
    }
    assertEquals(Duration.ofSeconds(60), partialFailureBackoff(2, Duration.ofSeconds(30)))
    assertEquals(Duration.ofSeconds(240), partialFailureBackoff(4, Duration.ofSeconds(30)))
    assertEquals(MAX_PARTIAL_BACKOFF, partialFailureBackoff(5, Duration.ofSeconds(30)))
  }

  // ------------------------------------------------- transport coverage --

  @Test
  fun marshalBatchCompressionFlag() {
    val cfg = defaultConfig()
    cfg.compressionThreshold = 100
    val tr = Transport(cfg, "install", null, quietLogger())
    val batch = EventBatch()
    batch.projectId = "p"
    batch.events = listOf(testEvent(1, "x".repeat(200)))
    val raw = tr.marshalBatch(batch)
    val parsed = parseJson(raw, useNumber = false) as Map<*, *>
    assertEquals(true, parsed["compressed"], "the compressed flag must be set truthfully")
    assertFalse(tr.willCompress(10), "tiny bodies stay uncompressed")
    assertTrue(tr.willCompress(200), "bodies above the threshold compress")
  }

  @Test
  fun encodeBodyCompression() {
    val cfg = defaultConfig()
    cfg.compressionThreshold = 16
    val tr = Transport(cfg, "install", null, quietLogger())
    val raw = "x".repeat(100).toByteArray()
    val (wire, encoding) = tr.encodeBody(raw)
    assertEquals("gzip", encoding)
    assertEquals(
        "x".repeat(100),
        GZIPInputStream(wire.inputStream()).readBytes().toString(Charsets.UTF_8),
        "the gzip bytes must round-trip",
    )
    val (plain, noEncoding) = tr.encodeBody("tiny".toByteArray())
    assertEquals("", noEncoding)
    assertTrue(plain.contentEquals("tiny".toByteArray()))
    // The Go TestEncodeBodyCloseFailure injects a failing gzip writer;
    // the port exercises the same fail-open branch through the seam.
    tr.newGzipWriter = { output ->
      object : java.util.zip.GZIPOutputStream(output) {
        override fun close() {
          throw java.io.IOException("close exploded")
        }
      }
    }
    val (fallback, fallbackEncoding) = tr.encodeBody(raw)
    assertEquals("", fallbackEncoding, "a failing writer must send uncompressed")
    assertTrue(fallback.contentEquals(raw))
  }

  @Test
  fun projectIDOrDefault() {
    val cfg = defaultConfig()
    val tr = Transport(cfg, "install", null, quietLogger())
    assertEquals("default", tr.projectIDOrDefault(), "empty project id renders the default")
    cfg.projectId = "acme"
    assertEquals("acme", tr.projectIDOrDefault())
  }

  @Test
  fun evaluateBatchResponse() {
    val tr = Transport(defaultConfig(), "install", null, quietLogger())
    var (outcome, err) = tr.evaluateBatchResponse("""{"success":true,"errors":[]}""".toByteArray())
    assertEquals(SendOutcome.ACCEPTED, outcome)
    assertEquals(null, err)
    val (partialOutcome, _) = tr.evaluateBatchResponse("""{"success":false}""".toByteArray())
    assertEquals(SendOutcome.PARTIAL, partialOutcome, "success:false must be partial")
    val (partialErrors, _) =
        tr.evaluateBatchResponse("""{"success":true,"errors":["x"]}""".toByteArray())
    assertEquals(SendOutcome.PARTIAL, partialErrors, "an errors list must be partial")
    val (malformed, malformedErr) = tr.evaluateBatchResponse("{not json".toByteArray())
    assertEquals(
        SendOutcome.PARTIAL,
        malformed,
        "a malformed body must requeue rather than lose the batch",
    )
    assertTrue(
        malformedErr != null && malformedErr!!.message!!.contains("malformed ingest response"),
    )
  }

  @Test
  fun userAgentString() {
    assertEquals("guard-agent-jvm/" + AGENT_VERSION, userAgent())
    assertNotEquals("", AGENT_VERSION)
  }

  @Test
  fun sleepContextSemantics() {
    assertTrue(sleepContext(AgentContext.NONE, Duration.ofMillis(1)), "a short sleep must succeed")
    val ctx = AgentContext.withTimeout(10)
    assertFalse(
        sleepContext(ctx, Duration.ofSeconds(1)),
        "a sleep past the deadline must report the context",
    )
    val canceled = AgentContext.withCancel()
    canceled.cancel()
    assertFalse(sleepContext(canceled, Duration.ofMillis(1)), "a canceled context must not sleep")
  }

  @Test
  fun truncate() {
    assertEquals("short", truncate("short", 10))
    assertEquals("0123456789", truncate("0123456789abcdef", 10))
  }

  @Test
  fun sendOutcomeConfirmsSemantics() {
    assertTrue(sendOutcomeConfirms(SendOutcome.ACCEPTED))
    assertTrue(sendOutcomeConfirms(SendOutcome.PERMANENT))
    assertFalse(sendOutcomeConfirms(SendOutcome.PARTIAL))
    assertFalse(sendOutcomeConfirms(SendOutcome.FAILED))
  }

  @Test
  fun canonicalItemsJSONShape() {
    val tr = Transport(defaultConfig(), "install", null, quietLogger())
    // Both kinds absent: the empty arrays stay pinned.
    val empty = tr.canonicalItemsJSON(null, null)
    assertEquals(linkedMapOf("events" to emptyList<Any?>(), "metrics" to emptyList<Any?>()), empty)
    val payload = tr.canonicalItemsJSON(listOf(testEvent(1)), listOf(testMetric(2)))
    val events = payload["events"] as List<*>
    val metrics = payload["metrics"] as List<*>
    assertEquals(1, events.size)
    assertEquals(1, metrics.size)
    // Integer-typed metric values must stay integers on the canonical
    // plaintext (UseNumber round trip), pinning the vector shape.
    val metric = metrics[0] as Map<*, *>
    assertEquals("2", (metric["value"] as JsonNumber).raw)
  }
}
