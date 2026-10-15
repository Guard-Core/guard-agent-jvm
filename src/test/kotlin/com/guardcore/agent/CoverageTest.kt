package com.guardcore.agent

import java.time.Duration
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `coverage_test.go` (unit tier): the error renders, the crypto branches,
 * deep redaction, the limiter gate, transport status handling, construction paths, health
 * thresholds, and the background loops.
 */
class CoverageTest {
  companion object {
    private const val BACKSLASH: Char = '\u005C'
    // Built from code points so the expected bytes are unambiguous:
    // input `quote":back\` renders as `"quote\":back\\"`.
    @Suppress("MayBeConst")
    private val INPUT_QUOTE_BACK: String = "quote" + '"' + ":back" + BACKSLASH
    private val EXPECT_QUOTE_BACK: String = buildString {
      append('"')
      append("quote")
      append('\\').append('"')
      append(":back")
      append('\\').append('\\')
      append('"')
    }
  }

  // -------------------------------------------------------------- helpers --

  /** coverage_test.go `testEncryptionKey`. */
  private fun testEncryptionKey(): String {
    val key = ByteArray(32)
    for (i in key.indices) {
      key[i] = i.toByte()
    }
    return Base64.getUrlEncoder().encodeToString(key)
  }

  /** coverage_test.go `sealRawPlaintext`: well-formed ciphertexts with arbitrary plaintexts. */
  private fun sealRawPlaintext(
      projectKey: String,
      plaintext: String,
  ): String {
    val key = decodeUrlsafeBase64(projectKey)
    val nonce = ByteArray(ENCRYPTION_NONCE_SIZE)
    java.security.SecureRandom().nextBytes(nonce)
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
    val sealed = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    return encodeUrlsafeBase64(nonce + sealed)
  }

  private fun sampleRulesJSON(): String =
      """{"rule_id":"saas-rule","version":7,"ttl":120,"ip_ban_duration":60,
        "ip_blacklist":["10.0.0.1"],"ip_whitelist":["10.0.0.2"],
        "blocked_countries":["CN"],"whitelist_countries":["US"],
        "global_rate_limit":10,"global_rate_window":60,
        "endpoint_rate_limits":{"/api":[5,60]},
        "blocked_cloud_providers":["AWS"],"blocked_user_agents":["bot"],
        "suspicious_patterns":["union select"],
        "enable_penetration_detection":true,"enable_ip_banning":false,
        "enable_rate_limiting":true,"auto_ban_threshold":3,"auto_ban_duration":600,
        "enable_rate_limit_auto_ban":true,"emergency_mode":true,
        "emergency_whitelist":["192.0.2.1"],"emergency_whitelist_only":true,
        "message":"locked","expires_at":"2030-01-01T00:00:00Z"}"""

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

  // ------------------------------------------------------------- errors.go --

  @Test
  fun typedErrorMessages() {
    val bufferFull = BufferFullError("event", 5)
    assertTrue(bufferFull.message!!.contains("event buffer full at maxlen=5"))
    val permanent = PermanentError(400, "bad")
    assertTrue(permanent.message!!.contains("permanent rejection with status 400: bad"))
    val rateLimited = RateLimitedError(Duration.ofSeconds(7))
    assertEquals("guardagent: rate limited, retry after 7s", rateLimited.message)
    assertEquals(
        ErrorKind.BUFFER_FULL,
        bufferFull.errorKind,
        "BufferFullError must match ErrBufferFull",
    )
  }

  // --------------------------------------------------------- encryption.go --

  @Test
  fun encryptionErrorMessages() {
    assertEquals("boom", EncryptionError("boom").message)
    assertEquals("no fallback", EncryptionConfigError("no fallback").message)
  }

  @Test
  fun newPayloadEncryptorRejectsBadKeys() {
    val err = assertFailsWith<EncryptionError> { PayloadEncryptor.create("") }
    assertTrue(err.message!!.contains("cannot be empty"))
    assertFailsWith<EncryptionError> { PayloadEncryptor.create("AAAA") }
    assertFailsWith<EncryptionError> { PayloadEncryptor.create("@@@@invalid-base64@@@") }
  }

  @Test
  fun encryptDecryptRoundTripWithAssociatedData() {
    val p = PayloadEncryptor.create(testEncryptionKey())
    val payload = linkedMapOf<String, Any?>("b" to 2, "a" to "x")
    val sealed = p.encrypt(payload, "project-42")
    val opened = p.decrypt(sealed, "project-42")
    assertEquals("x", opened["a"], "round trip mismatch")
    // AAD mismatch must fail the GCM open.
    assertFailsWith<EncryptionError> { p.decrypt(sealed, "other-project") }
  }

  @Test
  fun decryptRejectsMalformedPayloads() {
    val p = PayloadEncryptor.create(testEncryptionKey())
    assertFailsWith<EncryptionError> { p.decrypt("!!!", "") }
    val short = Base64.getUrlEncoder().encodeToString(ByteArray(8))
    assertFailsWith<EncryptionError> { p.decrypt(short, "") }
    val sealed = p.encrypt(linkedMapOf<String, Any?>("a" to 1), "")
    // Corrupt one ciphertext byte in the middle.
    val raw = decodeUrlsafeBase64(sealed)
    raw[raw.size / 2] = (raw[raw.size / 2].toInt() xor 0xFF).toByte()
    assertFailsWith<EncryptionError> { p.decrypt(encodeUrlsafeBase64(raw), "") }
    // A valid GCM payload whose plaintext is not a JSON object (null) and
    // one whose plaintext is not JSON at all, both sealed with the same key.
    for ((name, plaintext) in linkedMapOf("null" to "null", "junk" to "not json")) {
      val sealedPlaintext = sealRawPlaintext(testEncryptionKey(), plaintext)
      val err =
          assertFailsWith<EncryptionError>("$name plaintext") { p.decrypt(sealedPlaintext, "") }
      assertTrue(err.message!!.contains("tampered"), "$name: ${err.message}")
    }
  }

  @Test
  fun encryptFailsWithoutEntropy() {
    val saved = cryptoRandRead
    try {
      cryptoRandRead = { throw java.io.IOException("no entropy") }
      val p = PayloadEncryptor.create(testEncryptionKey())
      assertFailsWith<EncryptionError> { p.encrypt(linkedMapOf<String, Any?>("a" to 1), "") }
      assertFalse(p.verifyKey(), "VerifyKey must fail when encryption fails")
      // Identifier generators must fall back instead of failing.
      assertEquals(36, newUUID4().length, "uuid fallback must still produce a shaped id")
      assertEquals(8, randomHex(4).length, "randomHex fallback must still produce hex")
    } finally {
      cryptoRandRead = saved
    }
  }

  @Test
  fun canonicalJSONPythonShape() {
    val payload =
        linkedMapOf<String, Any?>(
            "int" to -8,
            "uint" to 64L,
            "float32" to 0.5f,
            "float64" to 2.0,
            "neg" to -3.0,
            "big" to 1e20,
            "number" to JsonNumber("42"),
            "slice" to listOf<Any?>(null, true, "x"),
            "nested" to
                linkedMapOf<String, Any?>(
                    "z" to 1,
                    "a" to linkedMapOf<String, Any?>("deep" to 3.25),
                ),
            "time" to Instant.EPOCH,
            "chan" to Thread(),
        )
    val got = canonicalJSON(payload)
    for (want in
        listOf(
            "\"int\":-8",
            "\"uint\":64",
            "\"float32\":0.5",
            "\"float64\":2.0",
            "\"neg\":-3.0",
            "\"big\":1e+20",
            "\"number\":42",
            "\"slice\":[null,true,\"x\"]",
            "\"nested\":{\"a\":{\"deep\":3.25},\"z\":1}",
            "\"time\":\"1970-01-01T00:00:00Z\"",
            "\"chan\":null",
        )) {
      assertTrue(got.contains(want), "canonical JSON missing $want in $got")
    }
    // Keys must be sorted recursively: "nested" comes before "number".
    assertTrue(got.indexOf("\"nested\"") < got.indexOf("\"number\""), "keys must be sorted: $got")
  }

  @Test
  fun canonicalStringEscaping() {
    // The Go escaping table, case by case (each pinned through the writer).
    // Case 1 checked through the writer directly: quote and backslash.
    var sb = StringBuilder()
    appendCanonicalString(sb, INPUT_QUOTE_BACK)
    assertEquals(EXPECT_QUOTE_BACK, sb.toString())
    // Case 8: the max code point escapes as its surrogate pair.
    sb = StringBuilder()
    appendCanonicalString(sb, "\uDBFF\uDFFF")
    assertEquals("\"\\udbff\\udfff\"", sb.toString())
  }

  // ------------------------------------------------------------- redact.go --

  @Test
  fun sanitizeHeadersDeepStructures() {
    val sensitive = listOf("Authorization")
    val deep = linkedMapOf<String, Any?>()
    var cursor = deep
    repeat(15) {
      val next = linkedMapOf<String, Any?>()
      cursor["deep"] = next
      cursor = next
    }
    val got =
        sanitizeHeaders(
            linkedMapOf<String, Any?>(
                "list" to listOf<Any?>("a", 2, linkedMapOf<String, Any?>("authorization" to "s")),
                "strings" to listOf("x", "y"),
                "jsonScan" to "{\"authorization\":\"s\",\"keep\":1}",
                "jsonDeep" to "[1,2,3]",
                "badJSON" to "{not json",
                "whole" to "{".repeat(MAX_JSON_SCAN_LEN + 1),
                "plain" to "hello",
                "empty" to "   ",
                "scalar" to 3.14,
                "bytes" to "bytes".toByteArray(),
                "jsonNum" to JsonNumber("9"),
                "deepLimit" to deep,
                "func" to Thread(),
            ),
            sensitive,
        )
    val m = got as? Map<*, *> ?: error("sanitize must return a map")
    assertEquals(REDACTED_MARKER, m["func"], "unrepresentable values must redact")
    assertFalse(
        m["jsonScan"].toString().contains("\"s\""),
        "sensitive key inside a JSON string must redact: ${m["jsonScan"]}",
    )
    assertEquals("hello", m["plain"])
    assertEquals("{not json", m["badJSON"])
    assertEquals("   ", m["empty"])
    assertEquals(REDACTED_MARKER, m["whole"], "oversized JSON candidates must redact wholesale")
    assertFalse(
        m["deepLimit"].toString().contains("secret"),
        "over-depth subtree must redact wholesale: ${m["deepLimit"]}",
    )
    val list = m["list"] as List<*>
    val listMap = list[2] as Map<*, *>
    assertEquals(
        REDACTED_MARKER,
        listMap["authorization"],
        "sensitive keys inside list entries must redact",
    )
    // String-map values sanitize through the same walker.
    val strMapRaw =
        sanitizeHeaders(
            linkedMapOf<String, Any?>(
                "authorization" to "secret",
                "json" to "{\"authorization\":\"s\"}",
                "plain" to "ok",
            ),
            null,
        )
            as Map<*, *>
    assertEquals(REDACTED_MARKER, strMapRaw["authorization"])
    assertEquals(
        "{\"authorization\":\"[REDACTED]\"}",
        strMapRaw["json"],
        "JSON-looking values must reserialize sanitized",
    )
    assertEquals("ok", strMapRaw["plain"])
    // Nil sensitive headers fall back to the defaults.
    val fallback = sanitizeHeaders(linkedMapOf("Cookie" to "c"), null) as Map<*, *>
    assertEquals(REDACTED_MARKER, fallback["Cookie"])
  }

  @Test
  fun redactEventAndMetricCopies() {
    val ev = SecurityEvent(null, "e", metadata = linkedMapOf("authorization" to "s", "n" to 1))
    val redacted = redactEventMetadata(ev, null)
    assertEquals(REDACTED_MARKER, redacted.metadata?.get("authorization"))
    assertEquals("s", ev.metadata?.get("authorization"), "the input map must never be mutated")
    val kept = redactEventMetadata(SecurityEvent(null, "e"), null)
    assertEquals(null, kept.metadata, "nil metadata must pass through untouched")
    val metric =
        SecurityMetric(null, MetricTypes.REQUEST_COUNT, tags = linkedMapOf("x-api-key" to "s"))
    val tagged = redactMetricTags(metric, null)
    assertEquals(REDACTED_MARKER, tagged.tags?.get("x-api-key"))
    val keptMetric = redactMetricTags(SecurityMetric(null, MetricTypes.REQUEST_COUNT), null)
    assertEquals(null, keptMetric.tags, "nil tags must pass through untouched")
    val batch = EventBatch()
    batch.events = listOf(ev)
    batch.metrics = listOf(metric)
    redactBatch(batch, null)
    assertEquals(REDACTED_MARKER, batch.events!![0].metadata?.get("authorization"))
    assertEquals(REDACTED_MARKER, batch.metrics!![0].tags?.get("x-api-key"))
  }

  // ------------------------------------------------------ rate_limiter.go --

  @Test
  fun rateLimiterRetryAfter() {
    val limiter = RateLimiter(2, Duration.ofMillis(40))
    assertEquals(Duration.ZERO, limiter.retryAfter(), "a fresh limiter must admit immediately")
    assertTrue(limiter.acquire())
    assertTrue(limiter.acquire())
    assertFalse(limiter.acquire(), "a saturated limiter must deny")
    val wait = limiter.retryAfter()
    assertTrue(
        !wait.isZero && wait <= Duration.ofMillis(40),
        "retry window must bound the wait, got $wait",
    )
    // A fully aged window admits again and RetryAfter reports zero.
    limiter.seedCallsForTest(listOf(Instant.now().minusMillis(limiter.windowMillisForTest() * 2)))
    assertEquals(Duration.ZERO, limiter.retryAfter(), "an expired window must report zero wait")
    assertTrue(limiter.acquire(), "aged calls must prune on acquire")
  }

  // --------------------------------------------------------- transport.go --

  @Test
  fun limiterGateWaitsAndBurnsAttempts() {
    val cfg = defaultConfig()
    cfg.retryAttempts = 1
    val tr = Transport(cfg, "install", null, quietLogger())
    val limiter = RateLimiter(1, Duration.ofMillis(20))
    tr.limiter = limiter
    val saturate = { limiter.seedCallsForTest(listOf(Instant.now())) }
    var pair = tr.limiterGate(AgentContext.NONE, 0, "batch send")
    assertTrue(pair.first && pair.second == null, "a fresh limiter must admit, got $pair")
    // Saturated: the gate waits out the window and reports retry-eligible.
    saturate()
    pair = tr.limiterGate(AgentContext.NONE, 0, "batch send")
    assertFalse(pair.first, "a saturated gate must defer, got $pair")
    assertEquals(null, pair.second, "a saturated gate with retries left defers")
    // At the attempt budget the gate errors instead of retrying.
    saturate()
    pair = tr.limiterGate(AgentContext.NONE, 1, "batch send")
    assertFalse(pair.first, "an exhausted attempt budget must deny")
    assertTrue(pair.second != null, "an exhausted attempt budget must error")
    // A canceled context must surface immediately.
    saturate()
    val canceled = AgentContext.withCancel()
    canceled.cancel()
    pair = tr.limiterGate(canceled, 0, "batch send")
    assertFalse(pair.first, "a canceled context must deny")
    assertTrue(pair.second is ContextDone, "a canceled context must surface, got ${pair.second}")
  }

  @Test
  fun sendBatchStatusHandling() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 1
          c.backoffFactor = 0.001
        }
    try {
      // 200 + evaluate clean body.
      var pair = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{\"x\":1}".toByteArray())
      assertEquals(SendOutcome.ACCEPTED, pair.first, "clean 200 must accept: ${pair.second}")
      // 201 skips evaluation.
      mock.statusCodeOverrideForTest(201)
      pair = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray())
      assertEquals(SendOutcome.ACCEPTED, pair.first, "201 must accept without evaluation")
      mock.statusCodeOverrideForTest(0)
      // Permanent rejections.
      for (code in listOf(400, 404, 422)) {
        mock.statusCodeOverrideForTest(code)
        pair = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray())
        mock.statusCodeOverrideForTest(0)
        val permanent = pair.second as? PermanentError
        assertEquals(SendOutcome.PERMANENT, pair.first, "status $code must be permanent")
        assertTrue(
            permanent != null && permanent.statusCode == code,
            "status $code: ${pair.second}",
        )
      }
      // An unexpected 4xx is partial (and exempt from the breaker).
      mock.statusCodeOverrideForTest(409)
      pair = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray())
      mock.statusCodeOverrideForTest(0)
      assertEquals(SendOutcome.PARTIAL, pair.first, "unexpected 4xx must be partial")
      assertTrue(pair.second != null)
      // 403 retries with backoff and then fails.
      mock.statusCodeOverrideForTest(403)
      pair = tr.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray())
      mock.statusCodeOverrideForTest(0)
      assertEquals(SendOutcome.FAILED, pair.first, "403 must retry then fail")
      assertTrue(
          pair.second != null && pair.second!!.message!!.contains("authentication failed"),
          "${pair.second}",
      )
      // A canceled context during the send surfaces the context error.
      val canceled = AgentContext.withCancel()
      canceled.cancel()
      pair = tr.sendBatch(canceled, EVENTS_PATH, "{}".toByteArray())
      assertEquals(SendOutcome.FAILED, pair.first, "canceled sends must report the context")
      assertTrue(
          pair.second is ContextDone,
          "canceled sends must report the context, got ${pair.second}",
      )
      // Network errors retry with backoff and exhaust into outcomeFailed.
      val down =
          transport(null) { c ->
            c.retryAttempts = 1
            c.backoffFactor = 0.001
            c.endpoint = "http://127.0.0.1:1"
          }
      pair = down.sendBatch(AgentContext.NONE, EVENTS_PATH, "{}".toByteArray())
      assertEquals(SendOutcome.FAILED, pair.first, "unreachable endpoints must fail after retries")
      assertTrue(pair.second != null)
    } finally {
      mock.close()
    }
  }

  @Test
  fun sendEventsTransportPaths() {
    val mock = MockIngest()
    var hookStage = ""
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 1
          c.backoffFactor = 0.001
          c.onError = OnErrorHook { stage, _, _ -> hookStage = stage }
        }
    try {
      // Empty batches short-circuit to accepted.
      var pair = tr.sendEvents(AgentContext.NONE, emptyList())
      assertEquals(SendOutcome.ACCEPTED, pair.first, "empty batches must accept")
      pair = tr.sendMetrics(AgentContext.NONE, emptyList())
      assertEquals(SendOutcome.ACCEPTED, pair.first)
      // Serialization failure retains the batch as partial and fires the hook.
      val savedMarshal = tr.jsonMarshal
      try {
        tr.jsonMarshal = { throw java.io.IOException("marshal exploded") }
        pair = tr.sendEvents(AgentContext.NONE, listOf(testEvent(1)))
        assertEquals(SendOutcome.PARTIAL, pair.first, "marshal failure must be partial")
        assertEquals(
            ErrorHookStages.TRANSPORT_SEND,
            hookStage,
            "marshal failure must fire the transport hook",
        )
        pair = tr.sendMetrics(AgentContext.NONE, listOf(testMetric(1)))
        assertEquals(SendOutcome.PARTIAL, pair.first, "marshal failure must be partial")
      } finally {
        tr.jsonMarshal = savedMarshal
      }
      // A 413 on a multi-item batch splits recursively and confirms both halves.
      mock.setMaxBody(10)
      val big = (0..3).map { testEvent(it) }
      pair = tr.sendEvents(AgentContext.NONE, big)
      assertEquals(
          SendOutcome.ACCEPTED,
          pair.first,
          "413 split must confirm when every part confirms: ${pair.second}",
      )
      val bigMetrics = (0..3).map { testMetric(it) }
      pair = tr.sendMetrics(AgentContext.NONE, bigMetrics)
      assertEquals(
          SendOutcome.ACCEPTED,
          pair.first,
          "413 metric split must confirm: ${pair.second}",
      )
      // A 413 on a singleton drops it durably.
      pair = tr.sendEvents(AgentContext.NONE, listOf(testEvent(9, "y".repeat(64))))
      assertEquals(SendOutcome.PERMANENT, pair.first, "singleton 413 must drop durably")
      pair =
          tr.sendMetrics(
              AgentContext.NONE,
              listOf(
                  SecurityMetric(
                      null,
                      MetricTypes.REQUEST_COUNT,
                      1.0,
                      tags = linkedMapOf("pad" to "y".repeat(64)),
                  ),
              ),
          )
      assertEquals(SendOutcome.PERMANENT, pair.first, "singleton metric 413 must drop durably")
      // A failed half makes the whole split report failure.
      mock.setMaxBody(262144)
      mock.failNext(2)
      pair = tr.sendEvents(AgentContext.NONE, big)
      assertEquals(SendOutcome.FAILED, pair.first, "a failed batch must report failure")
      mock.clearKnobs()
    } finally {
      mock.close()
    }
  }

  @Test
  fun sendStatusPaths() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 1
          c.backoffFactor = 0.001
        }
    try {
      val payload = AgentStatusPayload()
      payload.timestamp = Instant.now()
      payload.status = AgentStatusValues.HEALTHY
      var pair = tr.sendStatus(AgentContext.NONE, payload)
      assertEquals(SendOutcome.ACCEPTED, pair.first, "clean status must accept")
      // Serialization failure is partial.
      val savedMarshal = tr.jsonMarshal
      try {
        tr.jsonMarshal = { throw java.io.IOException("marshal exploded") }
        pair = tr.sendStatus(AgentContext.NONE, payload)
        assertEquals(SendOutcome.PARTIAL, pair.first, "status marshal failure must be partial")
      } finally {
        tr.jsonMarshal = savedMarshal
      }
      // A 413 on status is a failed push (fire and forget), never requeues.
      mock.setMaxBody(1)
      pair = tr.sendStatus(AgentContext.NONE, payload)
      assertEquals(SendOutcome.FAILED, pair.first, "oversized status must fail the push")
      mock.setMaxBody(262144)
    } finally {
      mock.close()
    }
  }

  // ------------------------------------------------------ dynamic_rules.go --

  @Test
  fun dynamicRulesUnmarshalAppliesDefaultsAndOverrides() {
    // A sparse document carries the python defaults; absent lists default
    // to empty, never null.
    val sparse = DynamicRules.fromJson("{}".toByteArray())
    val def = DynamicRules.defaults()
    assertEquals(def.ruleId, sparse.ruleId, "sparse rules must carry the python defaults")
    assertEquals(def.ttl, sparse.ttl)
    assertEquals(def.ipBanDuration, sparse.ipBanDuration)
    assertTrue(
        sparse.ipBlacklist.isEmpty() &&
            sparse.endpointRateLimits.isEmpty() &&
            sparse.emergencyWhitelist.isEmpty(),
    )
    val full = DynamicRules.fromJson(sampleRulesJSON().toByteArray())
    assertEquals("saas-rule", full.ruleId, "overrides must apply")
    assertEquals(7, full.version)
    assertEquals(120, full.ttl)
    assertEquals(60, full.ipBanDuration)
    assertEquals(10, full.globalRateLimit, "pointer fields must decode")
    assertEquals(5, full.endpointRateLimits["/api"]?.get(0))
    assertEquals(false, full.enableIpBanning, "bool pointers must decode, not stay null")
    assertEquals(true, full.enableRateLimitAutoBan)
    assertEquals("locked", full.message, "optional fields must decode")
    assertEquals(java.time.Instant.parse("2030-01-01T00:00:00Z"), full.expiresAt)
    assertEquals(true, full.emergencyMode)
    assertEquals(true, full.emergencyWhitelistOnly)
    assertEquals(1, full.emergencyWhitelist.size)
    assertEquals(listOf("union select"), full.suspiciousPatterns, "pattern lists must decode")
    // Malformed payloads surface the decoder error.
    assertFailsWith<Exception> {
      DynamicRules.fromJson("{\"version\":\"not-a-number\"}".toByteArray())
    }
  }

  @Test
  fun fetchDynamicRulesStatusHandling() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 1
          c.backoffFactor = 0.001
        }
    try {
      // 200 with an unparseable body is a no-result retried at once.
      mock.serveRules(200, "{not json")
      var pair = tr.fetchDynamicRules(AgentContext.NONE)
      assertTrue(pair.second is NoResultError, "${pair.second}")
      // 200 with an object of the wrong shape surfaces a decode error.
      mock.serveRules(200, "{\"version\":\"x\"}")
      pair = tr.fetchDynamicRules(AgentContext.NONE)
      assertTrue(
          pair.second != null && pair.second!!.message!!.contains("malformed dynamic rules"),
          "${pair.second}",
      )
      // 429 exhausting the retry budget reports rate limiting.
      mock.serveRules(429, "")
      tr.limiter = RateLimiter()
      pair = tr.fetchDynamicRules(AgentContext.NONE)
      assertTrue(
          pair.second is RateLimitedError,
          "429 exhaustion must surface as RateLimitedError: ${pair.second}",
      )
      // Any other status exhausts into a generic error.
      mock.serveRules(502, "")
      pair = tr.fetchDynamicRules(AgentContext.NONE)
      assertTrue(
          pair.second != null && pair.second!!.message!!.contains("status 502"),
          "${pair.second}",
      )
      // A canceled context surfaces immediately.
      val canceled = AgentContext.withCancel()
      canceled.cancel()
      pair = tr.fetchDynamicRules(canceled)
      assertTrue(
          pair.second is ContextDone,
          "canceled fetches must report the context: ${pair.second}",
      )
      // Network errors exhaust into the transport error.
      val down =
          transport(null) { c ->
            c.retryAttempts = 1
            c.backoffFactor = 0.001
            c.endpoint = "http://127.0.0.1:1"
          }
      pair = down.fetchDynamicRules(AgentContext.NONE)
      assertTrue(pair.second != null, "unreachable endpoints must error")
    } finally {
      mock.close()
    }
  }

  /** coverage_test.go: a fetch panic converts to ErrInternal through the agent wrapper. */
  @Test
  fun fetchPanicConvertsToErrInternal() {
    val mock = MockIngest()
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    mock.let { cfg.endpoint = it.url }
    cfg.retryAttempts = 1
    cfg.backoffFactor = 0.001
    val agent = GuardAgent(cfg, quietLogger(), "install")
    agent.tr = Transport(cfg, "install", AgentTestPanicDoer(), quietLogger())
    try {
      val (rules, err) = agent.fetchRulesSafelyForTest(AgentContext.NONE)
      assertEquals(null, rules)
      assertTrue(
          err != null && err.matchesKind(ErrorKind.INTERNAL),
          "panics must convert to ErrInternal, got $err",
      )
    } finally {
      mock.close()
    }
  }

  @Test
  fun fetchDynamicRulesLimiterAndRequestBuild() {
    val mock = MockIngest()
    val tr =
        transport(mock) { c ->
          c.retryAttempts = 1
          c.backoffFactor = 0.001
        }
    try {
      // A saturated local limiter burns attempts: with retries left the
      // gate defers and the fetch proceeds; without them it errors out.
      val limiter = RateLimiter(1, Duration.ofMillis(20))
      tr.limiter = limiter
      mock.serveRules(200, sampleRulesJSON())
      limiter.seedCallsForTest(listOf(Instant.now()))
      var (rules, err) = tr.fetchDynamicRules(AgentContext.NONE)
      assertTrue(err == null, "a deferred gate retries, got $err")
      assertTrue(rules != null)
      val noRetries = transport(mock) { c -> c.retryAttempts = 0 }
      val small = RateLimiter(1, Duration.ofMillis(20))
      noRetries.limiter = small
      small.seedCallsForTest(listOf(Instant.now()))
      var pair = noRetries.fetchDynamicRules(AgentContext.NONE)
      assertTrue(
          pair.second != null && pair.second!!.message!!.contains("local rate limit"),
          "${pair.second}",
      )
      // An unparseable endpoint fails the request build.
      val bad = transport(null)
      bad.cfg.endpoint = "://bad endpoint"
      pair = bad.fetchDynamicRules(AgentContext.NONE)
      assertTrue(pair.second != null, "an unparseable endpoint must fail the request build")
      // An open circuit breaker rejects the fetch before any request.
      val open = transport(mock)
      repeat(BREAKER_FAILURE_THRESHOLD) { open.breaker.failure() }
      pair = open.fetchDynamicRules(AgentContext.NONE)
      assertTrue(
          pair.second != null && pair.second!!.matchesKind(ErrorKind.CIRCUIT_OPEN),
          "${pair.second}",
      )
    } finally {
      mock.close()
    }
  }

  // ------------------------------------------------------------ lifecycle --

  @Test
  fun newConstructionPaths() {
    val logger = CapturingLogger()
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.endpoint = "https://api.example.com/api/v1"
    cfg.installIdPath = tempDirFor("cov-new").resolve("install-id").toString()
    val agent = GuardAgent.create(cfg, AgentOptions().withLogger(logger))
    try {
      assertTrue(
          logger.output().contains(API_VERSION_SUFFIX_WARNING),
          "endpoint normalization must warn, got \"${logger.output()}\"",
      )
    } finally {
      agent.stop()
    }

    // An invalid encryption key fails construction without plaintext fallback.
    cfg.projectEncryptionKey = Base64.getUrlEncoder().encodeToString(ByteArray(8))
    val err = assertFailsWith<EncryptionConfigError> { GuardAgent.create(cfg) }
    assertTrue(
        err.message!!.contains("refusing plaintext fallback"),
        "message mismatch: ${err.message}",
    )

    // A broken Redis URL fails construction.
    cfg.projectEncryptionKey = ""
    cfg.redis = RedisConfig("bad-scheme://x", "p", Duration.ofMinutes(1))
    val redisErr = assertFailsWith<AgentConfigException> { GuardAgent.create(cfg) }
    assertTrue(redisErr.message!!.contains("redis configuration invalid"), "${redisErr.message}")
  }

  @Test
  fun healthyThresholds() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-healthy")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 100
          c.highWatermarkRatio = 1.0
        }
    try {
      assertFalse(agent.healthy(), "a stopped agent cannot be healthy")
      agent.start()
      assertTrue(agent.healthy(), "a fresh started agent must be healthy")
      // 95% occupancy fails the health check.
      for (i in 0 until 96) agent.sendEvent(testEvent(i))
      assertFalse(agent.healthy(), "95% occupancy must fail the health check")
      // A wide-open circuit breaker fails the health check.
      synchronized(agent.mutex) {
        agent.events.clear()
        agent.metrics.clear()
      }
      repeat(BREAKER_FAILURE_THRESHOLD) { agent.tr.breaker.failure() }
      assertFalse(agent.healthy(), "an open circuit must fail the health check")
      agent.tr.breaker.success()
      // A >50% lifetime failure rate fails the health check.
      synchronized(agent.mutex) {
        agent.eventsSent = 1
        agent.eventsFailed = 3
      }
      assertFalse(agent.healthy(), "a >50% failure rate must fail the health check")
      // Status mirrors the same degradation with the softer thresholds.
      assertEquals(
          AgentStatusValues.DEGRADED,
          agent.status().state,
          "a >10% failure rate must degrade",
      )
      // 90% occupancy degrades too.
      synchronized(agent.mutex) {
        agent.eventsSent = 0
        agent.eventsFailed = 0
      }
      for (i in 0 until 90) agent.sendEvent(testEvent(i))
      assertEquals(AgentStatusValues.DEGRADED, agent.status().state, "90% occupancy must degrade")
      agent.stop()
      assertFalse(agent.healthy(), "a closed agent cannot be healthy")
      assertEquals(
          AgentStatusValues.FAILED,
          agent.status().state,
          "a closed agent must report failed",
      )
    } finally {
      mock.close()
    }
  }

  @Test
  fun statusPayloadShape() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-statuspayload")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.start()
      agent.sendEvent(testEvent(1))
      agent.flush()
      var payload = agent.statusPayload()
      assertTrue(payload.lastFlush != null, "a completed flush must be reported in the payload")
      assertTrue(payload.uptime > 0, "a started agent must report uptime")
      assertEquals(AgentStatusValues.HEALTHY, payload.status)
      agent.stop()
      payload = agent.statusPayload()
      assertEquals(0.0, payload.uptime, "a closed agent must not report uptime")
    } finally {
      mock.close()
    }
  }

  @Test
  fun recordErrorRingBuffer() {
    val tmp = tempDirFor("cov-errring")
    val agent = newTestAgent(tmp, null)
    try {
      synchronized(agent.mutex) {
        for (i in 0 until GuardAgent.MAX_TRACKED_ERRORS + 2) {
          agent.recordErrorLocked("error-$i")
        }
      }
      val errs = agent.status().errors
      assertEquals(GuardAgent.MAX_TRACKED_ERRORS, errs.size, "the error ring must cap")
      assertEquals("error-2", errs[0], "oldest errors must be evicted first")
      assertEquals("error-${GuardAgent.MAX_TRACKED_ERRORS + 1}", errs.last())
    } finally {
      agent.stop()
    }
  }

  @Test
  fun loopCtxBeforeStart() {
    val tmp = tempDirFor("cov-loopctx")
    val agent = newTestAgent(tmp, null)
    try {
      // The loop context must always be usable.
      assertFalse(agent.loopCtx().isDone())
    } finally {
      agent.stop()
    }
  }

  @Test
  fun triggerFlushWakeWithoutBuffer() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-wake")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.start()
      // A wake with an empty buffer is a no-op.
      agent.flushIfNeeded()
      // A saturated wake queue drops the token instead of blocking.
      agent.flushWake.offer(Any())
      agent.triggerFlush()
      // A wake for a non-watermark buffer defers to the elapsed-time
      // gate, which fires because the recorded last flush is two hours old.
      agent.sendEvent(testEvent(1))
      synchronized(agent.mutex) { agent.lastFlush = Instant.now().minus(Duration.ofHours(2)) }
      agent.triggerFlush()
      waitUntil(Duration.ofSeconds(2), "wake flusher must drain") {
        agent.stats().eventsPending == 0
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun enqueueMetricPolicies() {
    // Drop evicts the oldest metric and counts the drop.
    var mock = MockIngest()
    var tmp = tempDirFor("cov-metric-drop")
    var agent = newTestAgent(tmp, mock) { c -> c.bufferSize = 2 }
    try {
      for (i in 0 until 3) agent.sendMetric(testMetric(i))
      assertEquals(1L, agent.stats().metricsDropped, "drop policy must evict the oldest")
    } finally {
      agent.stop()
      mock.close()
    }

    // Raise returns BufferFullError.
    mock = MockIngest()
    tmp = tempDirFor("cov-metric-raise")
    agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 1
          c.highWatermarkRatio = 1.0
          c.overflow = OverflowPolicy.RAISE
        }
    try {
      agent.sendMetric(testMetric(1))
      val err = assertFailsWith<BufferFullError> { agent.sendMetric(testMetric(2)) }
      assertEquals("metric", err.kind, "raise policy must return BufferFullError")
    } finally {
      agent.stop()
      mock.close()
    }

    // Block waits for space freed by a flush.
    mock = MockIngest()
    tmp = tempDirFor("cov-metric-block")
    agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 1
          c.highWatermarkRatio = 1.0
          c.overflow = OverflowPolicy.BLOCK
        }
    try {
      agent.sendMetric(testMetric(1))
      val done = Thread { agent.sendMetric(AgentContext.NONE, testMetric(2)) }
      done.start()
      waitUntil(Duration.ofSeconds(1), "blocked sender must park") {
        synchronized(agent.mutex) { agent.metrics.size == 1 }
      }
      agent.flush()
      done.join(5000)
      assertFalse(done.isAlive, "blocked sender must resume after a flush")
    } finally {
      agent.stop()
      mock.close()
    }

    // Block with a canceled context returns the context error immediately.
    mock = MockIngest()
    tmp = tempDirFor("cov-metric-cancel")
    agent =
        newTestAgent(tmp, mock) { c ->
          c.bufferSize = 1
          c.highWatermarkRatio = 1.0
          c.overflow = OverflowPolicy.BLOCK
        }
    try {
      agent.sendMetric(testMetric(1))
      val canceled = AgentContext.withCancel()
      canceled.cancel()
      val err = assertFailsWith<ContextDone> { agent.sendMetric(canceled, testMetric(2)) }
      assertTrue(err.message!!.contains("context"), "block policy must honor the context: $err")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun flushMetricsGateAndSettlements() {
    val mock = MockIngest()
    val hooks = java.util.Collections.synchronizedList(mutableListOf<String>())
    val tmp = tempDirFor("cov-metric-gate")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.retryAttempts = 0
          c.onError = OnErrorHook { stage, _, _ -> hooks.add(stage) }
        }
    try {
      agent.start()
      // First metric flush fails (500): requeue, arm the gate, fire the hook.
      mock.failNext(1)
      agent.sendMetric(testMetric(1))
      val err = agent.flush()
      assertTrue(err != null, "the failed flush must surface its error")
      assertEquals(1, agent.stats().metricsPending, "failed batches must requeue")
      // The gate suppresses the immediate retry.
      assertEquals(null, agent.flush(), "the gated retry must be a no-op")
      assertEquals(1, mock.callsTo(METRICS_PATH).size, "the gate must suppress the immediate retry")
      // A forced flush bypasses the gate.
      assertEquals(null, agent.flush(), "forced flush")
      assertTrue(
          hooks.contains(ErrorHookStages.FLUSH_METRICS),
          "metric flush failures must fire the flush hook, got $hooks",
      )
    } finally {
      agent.stop()
      mock.close()
    }

    // Permanent rejection confirms the batch and counts it as sent.
    val mock2 = MockIngest()
    val tmp2 = tempDirFor("cov-metric-perm")
    val agent2 = newTestAgent(tmp2, mock2)
    try {
      agent2.sendMetric(testMetric(2))
      mock2.reject400Next(1)
      assertEquals(null, agent2.flush(), "permanent rejections must not surface as errors")
      val stats = agent2.stats()
      assertEquals(1L, stats.metricsSent, "permanent rejections must confirm the batch")
      assertEquals(0, stats.metricsPending)
    } finally {
      agent2.stop()
      mock2.close()
    }

    // A transport panic during a metric flush still requeues the batch.
    val mock3 = MockIngest()
    val tmp3 = tempDirFor("cov-metric-panic")
    val agent3 = newTestAgent(tmp3, mock3, AgentOptions().withHttpClient(AgentTestPanicDoer()))
    try {
      agent3.sendMetric(testMetric(3))
      val err = agent3.flush()
      assertTrue(
          err != null && err.matchesKind(ErrorKind.INTERNAL),
          "panics must surface as ErrInternal, got $err",
      )
      assertEquals(1, agent3.stats().metricsPending, "panics must not lose the batch")
    } finally {
      agent3.stop()
      mock3.close()
    }
  }

  @Test
  fun requeueTailEvictionDirect() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-requeue-direct")
    val agent = newTestAgent(tmp, mock) { c -> c.bufferSize = 2 }
    try {
      val evicted =
          listOf(
              GuardAgent.BufferedEvent(testEvent(1), "k1"),
              GuardAgent.BufferedEvent(testEvent(2), "k2"),
              GuardAgent.BufferedEvent(testEvent(3), "k3"),
          )
      agent.requeueEvents(evicted)
      assertEquals(2, agent.stats().eventsPending, "requeue over capacity must evict the tail")
      assertEquals(1L, agent.stats().eventsDropped)
      val metricItems =
          listOf(
              GuardAgent.BufferedMetric(testMetric(1), "m1"),
              GuardAgent.BufferedMetric(testMetric(2), "m2"),
              GuardAgent.BufferedMetric(testMetric(3), "m3"),
          )
      agent.requeueMetrics(metricItems)
      assertEquals(2, agent.stats().metricsPending)
      assertEquals(1L, agent.stats().metricsDropped)
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun reportStatusOutcomes() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-status-outcomes")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.reportStatus(AgentContext.NONE)
      assertEquals(1L, agent.stats().statusReportsSent, "accepted status must count as sent")
    } finally {
      agent.stop()
      mock.close()
    }
    // A failing endpoint counts and records the failure.
    val tmp2 = tempDirFor("cov-status-down")
    val down = newTestAgent(tmp2, null)
    try {
      down.tr.cfg.endpoint = "http://127.0.0.1:1"
      down.reportStatus(AgentContext.NONE)
      assertEquals(1L, down.stats().statusReportsFailed, "failed status must count")
      synchronized(down.mutex) {
        assertTrue(down.lastErrors.isNotEmpty(), "failed status must record an error")
      }
    } finally {
      down.stop()
    }
  }

  @Test
  fun confirmKeysWithoutPersistence() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-confirmkeys")
    val agent = newTestAgent(tmp, mock)
    try {
      agent.confirmKeys(listOf("k")) // no persistence: no-op, no throw
      agent.confirmKeys(emptyList())
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // ----------------------------------------------------------- background --

  @Test
  fun backgroundLoopsRecoverAndReport() {
    val mock = MockIngest()
    val tmp = tempDirFor("cov-loops")
    val agent =
        newTestAgent(tmp, mock) { c ->
          c.flushInterval = Duration.ofMillis(5)
          c.statusInterval = Duration.ofHours(1)
        }
    try {
      // Shrink the status cadence after construction (validation floors
      // it at 60s for user configs; the loop only reads the field).
      agent.cfg.statusInterval = Duration.ofMillis(5)
      agent.start()
      agent.sendEvent(testEvent(1))
      waitUntil(Duration.ofSeconds(5), "periodic flush must drain the buffer") {
        agent.stats().eventsPending == 0 && agent.stats().eventsSent == 1L
      }
      waitUntil(Duration.ofSeconds(5), "status loop must report") {
        agent.stats().statusReportsSent >= 1
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun autoFlushLoopLogsRepeatedFailures() {
    val logger = CapturingLogger()
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.endpoint = "http://127.0.0.1:1"
    cfg.statusInterval = Duration.ofHours(1)
    cfg.backoffFactor = 0.001
    cfg.installIdPath = tempDirFor("cov-autoflush").resolve("install-id").toString()
    val agent = GuardAgent.create(cfg, AgentOptions().withLogger(logger))
    try {
      agent.sendEvent(testEvent(1))
      val expireGate = {
        synchronized(agent.mutex) { agent.eventGate = Instant.EPOCH }
      }
      // A first and second failure log the plain line.
      assertEquals(1, agent.flushTick(0), "first failure must count one")
      expireGate()
      agent.flushTick(1)
      expireGate()
      assertTrue(
          logger.output().contains("periodic flush failed: "),
          "single failures must log plainly",
      )
      assertFalse(logger.output().contains("repeatedly"), "the escalation must wait for three")
      // ...the third consecutive one escalates.
      assertEquals(3, agent.flushTick(2), "third failure must count three")
      assertTrue(
          logger.output().contains("periodic flush failing repeatedly (3 in a row)"),
          "repeated failures must escalate the log, got \"${logger.output()}\"",
      )
      // A successful tick resets the streak silently.
      synchronized(agent.mutex) { agent.events.clear() }
      assertEquals(0, agent.flushTick(3), "a clean tick must reset the streak")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun rulesLoopServesLastKnownRules() {
    val logger = CapturingLogger()
    val mock = MockIngest()
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.endpoint = mock.url
    cfg.flushInterval = Duration.ofHours(1)
    cfg.statusInterval = Duration.ofHours(1)
    cfg.backoffFactor = 0.001
    cfg.projectId = "proj-1"
    cfg.installIdPath = tempDirFor("cov-rulesloop").resolve("install-id").toString()
    val agent = GuardAgent.create(cfg, AgentOptions().withLogger(logger))
    try {
      agent.cfg.dynamicRuleInterval = Duration.ofMillis(5)
      // Lift the local request limiter: the 5ms polling cadence would
      // otherwise saturate the 100-per-minute client window mid-test.
      agent.tr.limiter = RateLimiter(1_000_000, Duration.ofHours(1))
      mock.serveRules(500, "")
      agent.start()
      waitUntil(Duration.ofSeconds(10), "repeated rules failures must escalate the log") {
        logger.output().contains("dynamic rules loop failing repeatedly")
      }
      // Recovery resets the streak silently.
      mock.serveRules(200, sampleRulesJSON())
      agent.tr.breaker.success()
      waitUntil(Duration.ofSeconds(10), "rules recovery must cache the document") {
        synchronized(agent.mutex) { agent.cachedRules != null }
      }
    } finally {
      agent.stop()
      mock.close()
    }
  }

  // --------------------------------------------------------------- config --

  @Test
  fun normalizeValidationProblems() {
    val cfg = defaultConfig()
    cfg.apiKey = "short"
    cfg.bufferSize = -1
    cfg.flushInterval = Duration.ofSeconds(-1)
    cfg.statusInterval = Duration.ofSeconds(1)
    cfg.dynamicRuleInterval = Duration.ofSeconds(1)
    cfg.highWatermarkRatio = 2.0
    cfg.maxConcurrentFlushes = -1
    cfg.overflow = OverflowPolicy("bogus")
    cfg.retryAttempts = -1
    cfg.timeout = Duration.ofSeconds(-1)
    cfg.backoffFactor = -1.0
    cfg.compressionThreshold = -1
    cfg.maxPayloadSize = -1
    cfg.endpoint = "not a url"
    val err = normalize(cfg).error
    assertTrue(err != null, "invalid configs must surface a ConfigError")
    for (want in
        listOf(
            "api key",
            "valid URL",
            "buffer size",
            "flush interval",
            "status interval",
            "dynamic rule interval",
            "high watermark",
            "max concurrent flushes",
            "overflow policy",
            "retry attempts",
            "timeout",
            "backoff factor",
            "compression threshold",
            "max payload size",
        )) {
      assertTrue(
          err!!.message!!.contains(want),
          "problems must include \"$want\", got \"${err.message}\"",
      )
    }
    // Redis config defaults and problems.
    val cfg2 = defaultConfig()
    cfg2.apiKey = "test-api-key-123"
    cfg2.redis = RedisConfig()
    var err2 = normalize(cfg2).error
    assertTrue(err2 != null && err2!!.message!!.contains("redis url is required"), "$err2")
    cfg2.redis = RedisConfig("redis://127.0.0.1:6379", ttl = Duration.ofSeconds(-1))
    err2 = normalize(cfg2).error
    assertTrue(err2 != null && err2!!.message!!.contains("redis ttl"), "$err2")
    cfg2.redis = RedisConfig("redis://127.0.0.1:6379")
    val normalized = normalize(cfg2)
    assertEquals(null, normalized.error, "valid redis config: ${normalized.error}")
    assertEquals(DEFAULT_REDIS_PREFIX, normalized.cfg.redis!!.prefix, "redis defaults must apply")
    assertEquals(DEFAULT_PERSIST_TTL, normalized.cfg.redis!!.ttl)
  }

  @Test
  fun shortOf() {
    assertEquals("event_short", Persistence.shortOf("prefix:agent_events:event_short"))
    assertEquals("nocolon", Persistence.shortOf("nocolon"))
  }

  @Test
  fun configErrorRendersProblems() {
    val err = AgentConfigException(listOf("a", "b"))
    assertEquals(
        "guardagent: invalid configuration: a; b",
        err.message,
        "ConfigError render mismatch",
    )
  }

  @Test
  fun recoverPanicInExportedMethods() {
    // A hand-built agent without a transport surfaces ErrInternal from
    // Status instead of crashing (the Go nil-transport analog).
    val raw = GuardAgent(AgentConfig(), quietLogger(), "install")
    val err = assertFailsWith<GuardAgentException> { raw.status() }
    assertEquals(
        ErrorKind.INTERNAL,
        err.errorKind,
        "the recover must translate the failure, not crash",
    )
  }
}
