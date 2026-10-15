package com.guardcore.agent

import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.atomic.AtomicLong
import java.util.logging.Logger
import java.util.zip.GZIPOutputStream

/**
 * Port of guard-agent-go `transport.go`: the ingestion API shipping layer. Circuit breaker
 * admission, local rate limiter admission, gzip above the threshold, the HMAC signature over the
 * UNCOMPRESSED body, capped Retry-After on 429, 413 split-or-drop, and permanent-rejection
 * semantics.
 */

// Ingestion API paths.
public const val EVENTS_PATH: String = "/api/v1/events"
public const val METRICS_PATH: String = "/api/v1/metrics"
public const val STATUS_PATH: String = "/api/v1/status"

/** Replaces events and metrics when a project encryption key is configured. */
public const val ENCRYPTED_PATH: String = "/api/v1/events/encrypted"

/** The GET endpoint for SaaS dynamic rules (dynamic_rules.go `rulesPath`). */
public const val RULES_PATH: String = "/api/v1/rules"

internal const val MAX_RETRY_AFTER_SECONDS: Long = 300
internal const val DEFAULT_RETRY_AFTER_SECONDS: Long = 60
internal val MAX_RETRY_BACKOFF: Duration = Duration.ofSeconds(60)
internal val MAX_PARTIAL_BACKOFF: Duration = Duration.ofSeconds(300)
internal const val HTTP_READ_LIMIT: Int = 1 shl 20

/**
 * transport.go `sendOutcome`: the verdict of one batch send attempt group. It drives the
 * at-least-once handshake on the agent side.
 */
public enum class SendOutcome {
  /** The API confirmed the batch: persisted records are confirmed (deleted). */
  ACCEPTED,

  /**
   * A 200 carried success:false / errors, or an unusable response (unparseable or empty 200, 202,
   * 204, 3xx, 405, 408) outlasted the retry budget: requeue.
   */
  PARTIAL,

  /**
   * A definitive rejection (400/404/422, or a singleton 413): drop durably, confirm records, never
   * requeue.
   */
  PERMANENT,

  /** Retryable failure with attempts exhausted (network, 5xx, 401/403, 429): requeue. */
  FAILED,
}

/** transport.go `outcomeConfirms`: whether the outcome settles the batch. */
public fun sendOutcomeConfirms(o: SendOutcome): Boolean =
    o == SendOutcome.ACCEPTED || o == SendOutcome.PERMANENT

/**
 * The WithHTTPClient seam: dispatches one fully-built request and returns the response. The default
 * implementation never follows redirects, matching the reference agents.
 */
public fun interface HttpDoer {
  /**
   * Dispatches one fully-built request. The context rides along exactly like Go's request
   * WithContext: the default dispatcher watches for cancellation while the request is in flight.
   */
  public fun execute(
      request: HttpRequest,
      body: ByteArray,
      ctx: AgentContext,
  ): HttpResponse<ByteArray>
}

internal class Transport(
    internal val cfg: AgentConfig,
    internal val installId: String,
    httpClient: HttpDoer?,
    internal val logger: Logger,
) {
  internal val breaker = CircuitBreaker()
  internal var limiter: RateLimiter = RateLimiter(DEFAULT_LIMITER_MAX_CALLS, DEFAULT_LIMITER_WINDOW)
  internal var encryptor: PayloadEncryptor? = null

  internal val client: HttpDoer =
      httpClient
          ?: run {
            val javaClient =
                HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .apply {
                      if (!cfg.timeout.isZero && !cfg.timeout.isNegative)
                          connectTimeout(cfg.timeout)
                    }
                    .build()
            HttpDoer { request, _, ctx -> defaultDispatch(javaClient, request, ctx) }
          }

  /** The context-aware dispatch over java.net.http (the http.Client.Do(ctx) analog). */
  private fun defaultDispatch(
      javaClient: HttpClient,
      request: HttpRequest,
      ctx: AgentContext,
  ): HttpResponse<ByteArray> {
    val future = javaClient.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray())
    return try {
      while (true) {
        try {
          return future.get(25, java.util.concurrent.TimeUnit.MILLISECONDS)
        } catch (timeout: java.util.concurrent.TimeoutException) {
          if (ctx.isDone()) {
            future.cancel(true)
            throw ctx.err()
          }
        } catch (exec: java.util.concurrent.ExecutionException) {
          throw exec.cause ?: exec
        }
      }
      @Suppress("UNREACHABLE_CODE") error("unreachable")
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      future.cancel(true)
      throw java.io.IOException("interrupted", e)
    }
  }

  internal val requestsSent = AtomicLong(0)
  internal val requestsFailed = AtomicLong(0)
  internal val bytesSent = AtomicLong(0)

  // Test seams: package variables so tests can deterministically exercise
  // the defensive serialization/compression failure paths. Production always
  // uses the real marshaler, decoder, and gzip writer.
  internal var jsonMarshal: (Any?) -> ByteArray = ::goJsonMarshalDefault
  internal var newGzipWriter: (java.io.OutputStream) -> GZIPOutputStream = ::GZIPOutputStream
  internal var decodeGenericJSON: (ByteArray) -> Any? = { raw -> parseJson(raw, useNumber = true) }

  /** transport.go `fireHook`: routes a stage failure to the user's on_error callback. */
  private fun fireHook(
      stage: String,
      err: Throwable,
      context: Map<String, Any?>,
  ) {
    fireErrorHook(cfg.onError, logger, stage, err, context)
  }

  /**
   * transport.go `limiterGate`: mirrors the Python _send_with_retry/_get_with_retry pre-check:
   * acquire a local rate limiter slot before every attempt; when denied, wait the suggested
   * interval and burn an attempt, exactly like the Python `continue` inside the attempts loop.
   * Returns true to proceed; false to retry the loop; the error is the give-up verdict.
   */
  internal fun limiterGate(
      ctx: AgentContext,
      attempt: Int,
      what: String,
  ): Pair<Boolean, Throwable?> {
    if (limiter.acquire()) {
      return true to null
    }
    val wait = limiter.retryAfter()
    logger.warning(
        "guardagent: local rate limit exceeded, waiting " + wait.toMillis() + "ms before $what",
    )
    if (!sleepContext(ctx, wait)) {
      return false to ctx.err()
    }
    if (attempt >= cfg.retryAttempts) {
      return false to
          GuardAgentException(
              "guardagent: local rate limit prevented $what",
              ErrorKind.INTERNAL,
          )
    }
    return false to null
  }

  /** transport.go `sendEvents`: posts one events batch. */
  public fun sendEvents(
      ctx: AgentContext,
      events: List<SecurityEvent>,
  ): Pair<SendOutcome, Throwable?> {
    if (events.isEmpty()) {
      return SendOutcome.ACCEPTED to null
    }
    encryptor?.let {
      return sendEncryptedBatch(ctx, events, null)
    }
    val batch = EventBatch()
    batch.projectId = projectIDOrDefault()
    batch.events = events
    batch.batchId = newBatchID()
    batch.createdAt = java.time.Instant.now()
    batch.agentVersion = AGENT_VERSION
    batch.guardVersion = cfg.guardVersion.ifEmpty { null }
    batch.guardCoreVersion = cfg.guardCoreVersion.ifEmpty { null }
    val raw =
        try {
          marshalBatch(batch)
        } catch (err: Exception) {
          logger.warning(
              "guardagent: serialization failed for event batch, retaining batch: ${err.message}",
          )
          fireHook(
              ErrorHookStages.TRANSPORT_SEND,
              err,
              mapOf("endpoint" to EVENTS_PATH, "data_type" to "events"),
          )
          return SendOutcome.PARTIAL to err
        }
    val (outcome, err) = sendBatch(ctx, EVENTS_PATH, raw)
    if (err is PayloadTooLargeError) {
      return splitOrDropEvents(ctx, events) to null
    }
    if (outcome == SendOutcome.FAILED && err != null) {
      fireHook(
          ErrorHookStages.TRANSPORT_SEND,
          err,
          mapOf("endpoint" to EVENTS_PATH, "data_type" to "events"),
      )
    }
    return outcome to err
  }

  /**
   * transport.go `sendMetrics`: posts one metrics batch. Encrypted-mode handling matches
   * sendEvents.
   */
  public fun sendMetrics(
      ctx: AgentContext,
      metrics: List<SecurityMetric>,
  ): Pair<SendOutcome, Throwable?> {
    if (metrics.isEmpty()) {
      return SendOutcome.ACCEPTED to null
    }
    encryptor?.let {
      return sendEncryptedBatch(ctx, null, metrics)
    }
    val batch = EventBatch()
    batch.projectId = projectIDOrDefault()
    batch.metrics = metrics
    batch.batchId = newBatchID()
    batch.createdAt = java.time.Instant.now()
    batch.agentVersion = AGENT_VERSION
    batch.guardVersion = cfg.guardVersion.ifEmpty { null }
    batch.guardCoreVersion = cfg.guardCoreVersion.ifEmpty { null }
    val raw =
        try {
          marshalBatch(batch)
        } catch (err: Exception) {
          logger.warning(
              "guardagent: serialization failed for metric batch, retaining batch: ${err.message}",
          )
          fireHook(
              ErrorHookStages.TRANSPORT_SEND,
              err,
              mapOf("endpoint" to METRICS_PATH, "data_type" to "metrics"),
          )
          return SendOutcome.PARTIAL to err
        }
    val (outcome, err) = sendBatch(ctx, METRICS_PATH, raw)
    if (err is PayloadTooLargeError) {
      return splitOrDropMetrics(ctx, metrics) to null
    }
    if (outcome == SendOutcome.FAILED && err != null) {
      fireHook(
          ErrorHookStages.TRANSPORT_SEND,
          err,
          mapOf("endpoint" to METRICS_PATH, "data_type" to "metrics"),
      )
    }
    return outcome to err
  }

  /**
   * transport.go `sendEncryptedBatch`: encrypts the events/metrics arrays with AES-256-GCM and
   * POSTs the Python-shaped envelope. Serialization or encryption failure retains the batch
   * (requeue); a 413 halves the batch and sends each half re-encrypted, like the reference.
   */
  internal fun sendEncryptedBatch(
      ctx: AgentContext,
      events: List<SecurityEvent>?,
      metrics: List<SecurityMetric>?,
  ): Pair<SendOutcome, Throwable?> {
    val plaintext =
        try {
          canonicalItemsJSON(events, metrics)
        } catch (err: Exception) {
          logger.warning(
              "guardagent: serialization failed for encrypted batch, retaining batch: ${err.message}",
          )
          fireHook(ErrorHookStages.ENCRYPTION, err, mapOf("endpoint" to ENCRYPTED_PATH))
          return SendOutcome.PARTIAL to err
        }
    val encryptedPayload =
        try {
          encryptor!!.encrypt(plaintext, "")
        } catch (encErr: Exception) {
          logger.warning(
              "guardagent: encryption failed for batch, retaining batch: ${encErr.message}",
          )
          fireHook(ErrorHookStages.ENCRYPTION, encErr, mapOf("endpoint" to ENCRYPTED_PATH))
          return SendOutcome.PARTIAL to encErr
        }
    val envelope = EncryptedEnvelope()
    envelope.encryptedPayload = encryptedPayload
    envelope.batchId = newBatchID()
    envelope.agentVersion = AGENT_VERSION
    envelope.guardVersion = cfg.guardVersion.ifEmpty { null }
    envelope.guardCoreVersion = cfg.guardCoreVersion.ifEmpty { null }
    val encoded =
        try {
          jsonMarshal(envelope)
        } catch (err: Exception) {
          logger.warning(
              "guardagent: serialization failed for encrypted envelope, retaining batch: ${err.message}",
          )
          fireHook(ErrorHookStages.ENCRYPTION, err, mapOf("endpoint" to ENCRYPTED_PATH))
          return SendOutcome.PARTIAL to err
        }
    val (outcome, err) = sendBatch(ctx, ENCRYPTED_PATH, encoded)
    if (err is PayloadTooLargeError) {
      if (!events.isNullOrEmpty()) {
        return splitOrDropEvents(ctx, events) to null
      }
      return splitOrDropMetrics(ctx, metrics.orEmpty()) to null
    }
    return outcome to err
  }

  /**
   * transport.go `canonicalItemsJSON`: serializes only the events/metrics arrays into the exact
   * bytes Python json.dumps(..., sort_keys=True) emits. Items are round-tripped through a UseNumber
   * decoder so integer fields stay integers on the canonical plaintext.
   */
  internal fun canonicalItemsJSON(
      events: List<SecurityEvent>?,
      metrics: List<SecurityMetric>?,
  ): Map<String, Any?> {
    val payload =
        linkedMapOf<String, Any?>("events" to emptyList<Any?>(), "metrics" to emptyList<Any?>())
    if (!events.isNullOrEmpty()) {
      payload["events"] = decodeGenericJSON(jsonMarshal(events))
    }
    if (!metrics.isNullOrEmpty()) {
      payload["metrics"] = decodeGenericJSON(jsonMarshal(metrics))
    }
    return payload
  }

  /**
   * transport.go `sendStatus`: posts the periodic status report. Status is fire-and-forget: any
   * rejection is logged and counted as a failed push, never requeued.
   */
  internal fun sendStatus(
      ctx: AgentContext,
      payload: AgentStatusPayload,
  ): Pair<SendOutcome, Throwable?> {
    val raw =
        try {
          jsonMarshal(payload)
        } catch (err: Exception) {
          logger.warning("guardagent: serialization failed for status report: ${err.message}")
          return SendOutcome.PARTIAL to err
        }
    val (outcome, err) = sendBatch(ctx, STATUS_PATH, raw)
    // The reference's send_status turns a PermanentClientError or PayloadTooLargeError into a False
    // return: a rejected push is a failed push (never a success).
    if (err is PayloadTooLargeError) {
      logger.warning("guardagent: status report exceeds the ingestion payload limit; dropping")
      requestsFailed.incrementAndGet()
      return SendOutcome.FAILED to err
    }
    if (outcome == SendOutcome.PERMANENT) {
      requestsFailed.incrementAndGet()
      return SendOutcome.FAILED to err
    }
    return outcome to err
  }

  /**
   * transport.go `splitOrDropEvents`: 413 handling. A batch that still triggers 413 as a singleton
   * is durably dropped; otherwise the batch is halved and both halves are sent recursively. The
   * aggregate confirms only when every part confirmed, mirroring guard-agent (Python)
   * _split_or_drop_on_payload_too_large.
   */
  internal fun splitOrDropEvents(
      ctx: AgentContext,
      events: List<SecurityEvent>,
  ): SendOutcome {
    if (events.size <= 1) {
      logger.warning(
          "guardagent: single event still exceeds the ingestion payload limit; dropping durably",
      )
      requestsFailed.incrementAndGet()
      fireHook(
          ErrorHookStages.TRANSPORT_SEND,
          PayloadTooLargeError("singleton event exceeds the payload limit"),
          mapOf("data_type" to "events", "item_count" to events.size),
      )
      return SendOutcome.PERMANENT
    }
    val mid = events.size / 2
    val left = sendEvents(ctx, events.subList(0, mid)).first
    val right = sendEvents(ctx, events.subList(mid, events.size)).first
    if (sendOutcomeConfirms(left) && sendOutcomeConfirms(right)) {
      return SendOutcome.ACCEPTED
    }
    return SendOutcome.FAILED
  }

  internal fun splitOrDropMetrics(
      ctx: AgentContext,
      metrics: List<SecurityMetric>,
  ): SendOutcome {
    if (metrics.size <= 1) {
      logger.warning(
          "guardagent: single metric still exceeds the ingestion payload limit; dropping durably",
      )
      requestsFailed.incrementAndGet()
      fireHook(
          ErrorHookStages.TRANSPORT_SEND,
          PayloadTooLargeError("singleton metric exceeds the payload limit"),
          mapOf("data_type" to "metrics", "item_count" to metrics.size),
      )
      return SendOutcome.PERMANENT
    }
    val mid = metrics.size / 2
    val left = sendMetrics(ctx, metrics.subList(0, mid)).first
    val right = sendMetrics(ctx, metrics.subList(mid, metrics.size)).first
    if (sendOutcomeConfirms(left) && sendOutcomeConfirms(right)) {
      return SendOutcome.ACCEPTED
    }
    return SendOutcome.FAILED
  }

  /**
   * transport.go `marshalBatch`: serializes a batch and marks the compressed flag truthfully (the
   * flag is informational on the server). Every outgoing batch body is redacted again at
   * serialization time, mirroring the Python transport's second redaction pass.
   */
  internal fun marshalBatch(batch: EventBatch): ByteArray {
    redactBatch(batch, cfg.sensitiveHeaders)
    batch.events = batch.events ?: emptyList()
    batch.metrics = batch.metrics ?: emptyList()
    var raw = jsonMarshal(batch)
    if (willCompress(raw.size)) {
      batch.compressed = true
      raw = jsonMarshal(batch)
    }
    return raw
  }

  internal fun willCompress(rawLen: Int): Boolean =
      cfg.compressionEnabled && rawLen >= cfg.compressionThreshold

  internal fun projectIDOrDefault(): String = cfg.projectId.ifEmpty { "default" }

  /**
   * transport.go `sendBatch`: the retry loop for one batch: circuit breaker admission, gzip when
   * enabled, the HMAC signature over the UNCOMPRESSED body, and status-specific outcome handling.
   *
   * Status code handling mirrors guard-agent (Python) _transport_dispatch: 200/201 success (200
   * evaluated for partial failure), 429 honored via capped Retry-After, 413 split-or-drop,
   * 400/404/422 permanent, 401/403 and 5xx and network errors retried with exponential backoff, any
   * other status a transient no-result retried at once without the breaker.
   */
  internal fun sendBatch(
      ctx: AgentContext,
      path: String,
      raw: ByteArray,
  ): Pair<SendOutcome, Throwable?> {
    val (wire, contentEncoding) = encodeBody(raw)
    val signature =
        if (cfg.signingSecret.isNotEmpty()) {
          // The server verifies the signature AFTER decompressing, so it must
          // cover the uncompressed body even when the wire bytes are gzipped.
          signPayload(raw, cfg.signingSecret)
        } else {
          ""
        }
    var attempt = 0
    while (true) {
      val (allowed, gateErr) = limiterGate(ctx, attempt, "batch send")
      if (!allowed) {
        if (gateErr != null) {
          return SendOutcome.FAILED to gateErr
        }
        continue
      }
      try {
        breaker.admit()
      } catch (err: GuardAgentException) {
        return SendOutcome.FAILED to err
      }
      // A pre-canceled context fails the send exactly like Go's
      // http.Client.Do(ctx) refusing to start the request.
      if (ctx.isDone()) {
        return SendOutcome.FAILED to ctx.err()
      }
      val request: HttpRequest
      try {
        val builder = HttpRequest.newBuilder().uri(URI.create(cfg.endpoint + path))
        if (!cfg.timeout.isZero && !cfg.timeout.isNegative) {
          builder.timeout(cfg.timeout)
        }
        if (contentEncoding.isNotEmpty()) {
          builder.header("Content-Encoding", contentEncoding)
        }
        if (signature.isNotEmpty()) {
          builder.header(SIGNATURE_HEADER, signature)
        }
        builder.header("Content-Type", "application/json")
        builder.header("User-Agent", userAgent())
        builder.header("X-API-Key", cfg.apiKey)
        builder.header("X-Agent-Install-Id", installId)
        if (cfg.projectId.isNotEmpty()) {
          builder.header("X-Project-Id", cfg.projectId)
        }
        builder.POST(HttpRequest.BodyPublishers.ofByteArray(wire))
        request = builder.build()
      } catch (err: Exception) {
        requestsFailed.incrementAndGet()
        return SendOutcome.FAILED to err
      }
      val response: HttpResponse<ByteArray>
      try {
        bytesSent.addAndGet(wire.size.toLong())
        response = client.execute(request, wire, ctx)
      } catch (err: ContextDone) {
        // A cancelled context is the caller stopping, not a transport fault: asyncio
        // CancelledError bypasses the reference breaker.
        return SendOutcome.FAILED to err
      } catch (err: java.io.IOException) {
        if (ctx.isDone()) {
          return SendOutcome.FAILED to ctx.err()
        }
        breaker.failure()
        requestsFailed.incrementAndGet()
        if (
            attempt < cfg.retryAttempts &&
                sleepContext(ctx, retryBackoff(attempt, cfg.backoffFactor))
        ) {
          attempt++
          continue
        }
        return SendOutcome.FAILED to err
      } catch (panic: Throwable) {
        // A panicking dispatcher (the Go RoundTripper panic analog)
        // propagates to the agent's safe wrapper instead of masquerading as
        // a network error.
        throw panic
      }
      val body = readLimited(response.body())
      when {
        response.statusCode() == 200 || response.statusCode() == 201 -> {
          breaker.success()
          val (outcome, evalErr) =
              if (response.statusCode() == 200) evaluateBatchResponse(body)
              else SendOutcome.ACCEPTED to null
          if (outcome == SendOutcome.ACCEPTED) {
            requestsSent.incrementAndGet()
          } else {
            requestsFailed.incrementAndGet()
          }
          if (evalErr is NoResultError && attempt < cfg.retryAttempts) {
            attempt++
            continue
          }
          return outcome to evalErr
        }
        response.statusCode() == 429 -> {
          breaker.failure()
          requestsFailed.incrementAndGet()
          val delay = parseRetryAfter(response.headers().firstValue("Retry-After").orElse(""))
          if (attempt < cfg.retryAttempts && sleepContext(ctx, delay)) {
            attempt++
            continue
          }
          return SendOutcome.FAILED to RateLimitedError(delay)
        }
        response.statusCode() == 413 -> {
          // A definitive server verdict about size, not transport health:
          // exempt from the breaker like permanent rejections.
          return SendOutcome.FAILED to
              PayloadTooLargeError(truncate(body.toString(Charsets.UTF_8), 200))
        }
        response.statusCode() == 400 ||
            response.statusCode() == 404 ||
            response.statusCode() == 422 -> {
          return SendOutcome.PERMANENT to
              PermanentError(response.statusCode(), truncate(body.toString(Charsets.UTF_8), 200))
        }
        response.statusCode() >= 500 -> {
          breaker.failure()
          requestsFailed.incrementAndGet()
          if (
              attempt < cfg.retryAttempts &&
                  sleepContext(ctx, retryBackoff(attempt, cfg.backoffFactor))
          ) {
            attempt++
            continue
          }
          return SendOutcome.FAILED to
              GuardAgentException(
                  "guardagent: server error " +
                      response.statusCode() +
                      ": " +
                      truncate(body.toString(Charsets.UTF_8), 200),
                  ErrorKind.INTERNAL,
              )
        }
        response.statusCode() == 401 || response.statusCode() == 403 -> {
          breaker.failure()
          requestsFailed.incrementAndGet()
          if (
              attempt < cfg.retryAttempts &&
                  sleepContext(ctx, retryBackoff(attempt, cfg.backoffFactor))
          ) {
            attempt++
            continue
          }
          return SendOutcome.FAILED to
              GuardAgentException(
                  "guardagent: authentication failed with status " + response.statusCode(),
                  ErrorKind.INTERNAL,
              )
        }
        else -> {
          // Any status the reference does not list (202, 204, 3xx, 405, 408, ...): a transient
          // no-result, retried at once, no breaker.
          breaker.success()
          requestsFailed.incrementAndGet()
          if (attempt < cfg.retryAttempts) {
            attempt++
            continue
          }
          return SendOutcome.PARTIAL to
              NoResultError("guardagent: unexpected status " + response.statusCode())
        }
      }
    }
  }

  /**
   * transport.go `encodeBody`: applies gzip when enabled and the uncompressed body meets the
   * threshold, returning the wire bytes and the Content-Encoding value.
   */
  internal fun encodeBody(raw: ByteArray): Pair<ByteArray, String> {
    if (!willCompress(raw.size)) {
      return raw to ""
    }
    return try {
      val buf = ByteArrayOutputStream()
      val gz = newGzipWriter(buf)
      gz.use { it.write(raw) }
      buf.toByteArray() to "gzip"
    } catch (err: Exception) {
      logger.warning("guardagent: gzip compression failed, sending uncompressed: ${err.message}")
      raw to ""
    }
  }

  /**
   * transport.go `evaluateBatchResponse`: mirrors _evaluate_send_result over a 200 body: only an
   * explicit success:false or a truthy errors value is a partial failure (requeue, no retry); an
   * unparseable body or an empty JSON object is a no-result ([NoResultError], retried at once); any
   * other body, including a non-object JSON value or an object without success, is accepted.
   */
  internal fun evaluateBatchResponse(body: ByteArray): Pair<SendOutcome, Throwable?> {
    val parsed =
        try {
          parseJson(body, useNumber = false)
        } catch (err: Exception) {
          return SendOutcome.PARTIAL to
              NoResultError("guardagent: malformed ingest response: ${err.message}")
        }
    val map = parsed as? Map<*, *> ?: return SendOutcome.ACCEPTED to null
    if (map["success"] == false || isTruthy(map["errors"])) {
      return SendOutcome.PARTIAL to null
    }
    if (map.isEmpty()) {
      return SendOutcome.PARTIAL to NoResultError("guardagent: empty ingest response object")
    }
    return SendOutcome.ACCEPTED to null
  }

  private fun readLimited(body: ByteArray): ByteArray =
      if (body.size > HTTP_READ_LIMIT) body.copyOf(HTTP_READ_LIMIT) else body

  internal fun closeIdleConnections() {
    // java.net.http pools internally; nothing to force-close per client.
  }
}

/**
 * Marks a response the reference maps to "no result" (an unparseable or empty-object 200, 202, 204,
 * 3xx, 405, 408 and any other unlisted status): retried at once, never opens the breaker and is
 * never accepted (_handle_response returns False, _send_with_retry loops).
 */
internal class NoResultError(
    message: String,
) : GuardAgentException(message, ErrorKind.INTERNAL)

/** Python truthiness of a decoded JSON value. */
internal fun isTruthy(v: Any?): Boolean =
    when (v) {
      null -> false
      is Boolean -> v
      is Number -> v.toDouble() != 0.0
      is String -> v.isNotEmpty()
      is Collection<*> -> v.isNotEmpty()
      is Map<*, *> -> v.isNotEmpty()
      else -> true
    }

/**
 * The default jsonMarshal seam target: encoding/json for the agent's wire domain (see [goJson]).
 */
internal fun goJsonMarshalDefault(v: Any?): ByteArray = goJson(v)

/** transport.go `parseRetryAfter`: clamped to [0, 300s], defaulting to 60s. */
internal fun parseRetryAfter(header: String): Duration {
  val trimmed = header.trim()
  val secs: Double =
      trimmed.toIntOrNull()?.toDouble()
          ?: trimmed.toDoubleOrNull()
          ?: DEFAULT_RETRY_AFTER_SECONDS.toDouble()
  val clamped = secs.coerceIn(0.0, MAX_RETRY_AFTER_SECONDS.toDouble())
  return Duration.ofMillis((clamped * 1000).toLong())
}

/** transport.go `retryBackoff`: min(backoff_factor * 2^attempt, 60s). */
internal fun retryBackoff(
    attempt: Int,
    factor: Double,
): Duration {
  if (attempt > 30) {
    return MAX_RETRY_BACKOFF
  }
  val d = Duration.ofMillis((factor * Math.pow(2.0, attempt.toDouble()) * 1000).toLong())
  if (d.isZero || d.isNegative) {
    return Duration.ofSeconds(1)
  }
  if (d > MAX_RETRY_BACKOFF) {
    return MAX_RETRY_BACKOFF
  }
  return d
}

/**
 * transport.go `partialFailureBackoff`: min(flush_interval * 2^(streak-1), 300s), the per-kind gate
 * applied after a failed flush cycle.
 */
internal fun partialFailureBackoff(
    streakIn: Int,
    interval: Duration,
): Duration {
  val streak = if (streakIn < 1) 1 else streakIn
  val d = Duration.ofMillis((interval.toMillis() * Math.pow(2.0, (streak - 1).toDouble())).toLong())
  if (d.isZero || d.isNegative || d > MAX_PARTIAL_BACKOFF) {
    return MAX_PARTIAL_BACKOFF
  }
  return d
}

/** transport.go `sleepCtx`: sleeps d, returning false when ctx ended first. */
internal fun sleepContext(
    ctx: AgentContext,
    d: Duration,
): Boolean {
  if (d.isZero || d.isNegative) {
    return !ctx.isDone()
  }
  val target = System.nanoTime() + d.toNanos()
  while (true) {
    if (ctx.isDone()) {
      return false
    }
    val remaining = target - System.nanoTime()
    if (remaining <= 0) {
      return true
    }
    try {
      Thread.sleep(
          Math.min(remaining, 5_000_000L) / 1_000_000,
          (Math.min(remaining, 5_000_000L) % 1_000_000).toInt(),
      )
    } catch (e: InterruptedException) {
      Thread.currentThread().interrupt()
      return false
    }
  }
}

internal fun truncate(
    s: String,
    n: Int,
): String = if (s.length <= n) s else s.substring(0, n)
