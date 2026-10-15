package com.guardcore.agent

import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong

/**
 * Port of guard-agent-go `models.go`: the telemetry model types with their encoding/json wire
 * shapes (snake_case, omitempty), the ingestion API vocabularies, and the identifier generators.
 */

/** Metric type values accepted by the ingestion API SecurityMetric model. */
public object MetricTypes {
  public const val REQUEST_COUNT: String = "request_count"
  public const val RESPONSE_TIME: String = "response_time"
  public const val ERROR_RATE: String = "error_rate"
  public const val BANDWIDTH_USAGE: String = "bandwidth_usage"
  public const val THREAT_LEVEL: String = "threat_level"
  public const val BLOCK_RATE: String = "block_rate"
  public const val CACHE_HIT_RATE: String = "cache_hit_rate"

  /** models.go `validMetricType`. */
  public fun isValid(type: String): Boolean = type in knownMetricTypes

  private val knownMetricTypes: Set<String> =
      setOf(
          REQUEST_COUNT,
          RESPONSE_TIME,
          ERROR_RATE,
          BANDWIDTH_USAGE,
          THREAT_LEVEL,
          BLOCK_RATE,
          CACHE_HIT_RATE,
      )
}

/** Agent status values reported on POST /api/v1/status. */
public object AgentStatusValues {
  public const val HEALTHY: String = "healthy"
  public const val DEGRADED: String = "degraded"
  public const val FAILED: String = "failed"
}

/**
 * models.go `KnownEventTypes`: every event type the guard ecosystem emits, mirroring
 * guard_agent.models.KNOWN_EVENT_TYPES (39 entries). It is documentation, not validation: like the
 * Python agent, sendEvent accepts any non-empty event type so new engine events cannot be dropped
 * at the consumer.
 */
public val KnownEventTypes: List<String> =
    listOf(
        "ip_banned",
        "ip_unbanned",
        "ip_blocked",
        "ip_ban_failed",
        "rate_limited",
        "rate_limit_script_reloaded",
        "suspicious_request",
        "cloud_blocked",
        "country_blocked",
        "penetration_attempt",
        "behavioral_violation",
        "user_agent_blocked",
        "custom_request_check",
        "decorator_violation",
        "decoding_error",
        "detection_engine_callback_error",
        "geo_lookup_failed",
        "https_enforced",
        "pattern_anomaly_slow_execution",
        "pattern_anomaly_timeout",
        "pattern_anomaly_statistical_anomaly",
        "redis_connection",
        "redis_error",
        "dynamic_rule_applied",
        "dynamic_rule_updated",
        "path_excluded",
        "route_unresolved",
        "pattern_detected",
        "pattern_added",
        "pattern_removed",
        "access_denied",
        "authentication_failed",
        "content_filtered",
        "emergency_mode_activated",
        "emergency_mode_block",
        "dynamic_rule_violation",
        "security_bypass",
        "security_headers_applied",
        "csp_violation",
    )

/** models.go `IsKnownEventType`. */
public fun isKnownEventType(eventType: String): Boolean = eventType in KnownEventTypes

/**
 * models.go `SecurityEvent`: one security telemetry event. The JSON shape matches
 * guard_agent.models.SecurityEvent field for field; the ingestion API requires timestamp and
 * event_type and allows extra fields. A null timestamp is the Go zero time (sendEvent defaults it
 * to now UTC).
 */
public class SecurityEvent {
  public var timestamp: Instant? = null
  public var eventType: String = ""
  public var idempotencyKey: String? = null
  public var ipAddress: String? = null
  public var country: String? = null
  public var userAgent: String? = null
  public var actionTaken: String? = null
  public var reason: String? = null
  public var endpoint: String? = null
  public var method: String? = null
  public var statusCode: Int? = null
  public var responseTime: Double? = null
  public var decoratorType: String? = null
  public var ruleType: String? = null
  public var patternMatched: String? = null
  public var handlerName: String? = null
  public var metadata: Map<String, Any?>? = null

  public constructor()

  public constructor(
      timestamp: Instant?,
      eventType: String,
      idempotencyKey: String? = null,
      ipAddress: String? = null,
      country: String? = null,
      userAgent: String? = null,
      actionTaken: String? = null,
      reason: String? = null,
      endpoint: String? = null,
      method: String? = null,
      statusCode: Int? = null,
      responseTime: Double? = null,
      decoratorType: String? = null,
      ruleType: String? = null,
      patternMatched: String? = null,
      handlerName: String? = null,
      metadata: Map<String, Any?>? = null,
  ) {
    this.timestamp = timestamp
    this.eventType = eventType
    this.idempotencyKey = idempotencyKey
    this.ipAddress = ipAddress
    this.country = country
    this.userAgent = userAgent
    this.actionTaken = actionTaken
    this.reason = reason
    this.endpoint = endpoint
    this.method = method
    this.statusCode = statusCode
    this.responseTime = responseTime
    this.decoratorType = decoratorType
    this.ruleType = ruleType
    this.patternMatched = patternMatched
    this.handlerName = handlerName
    this.metadata = metadata
  }

  public fun copy(): SecurityEvent =
      SecurityEvent(
          timestamp,
          eventType,
          idempotencyKey,
          ipAddress,
          country,
          userAgent,
          actionTaken,
          reason,
          endpoint,
          method,
          statusCode,
          responseTime,
          decoratorType,
          ruleType,
          patternMatched,
          handlerName,
          metadata,
      )
}

/**
 * models.go `SecurityMetric`: one numeric telemetry sample. MetricType must be one of the
 * [MetricTypes] constants.
 */
public class SecurityMetric {
  public var timestamp: Instant? = null
  public var metricType: String = ""
  public var value: Double = 0.0
  public var endpoint: String? = null
  public var tags: Map<String, String>? = null

  public constructor()

  public constructor(
      timestamp: Instant?,
      metricType: String,
      value: Double = 0.0,
      endpoint: String? = null,
      tags: Map<String, String>? = null,
  ) {
    this.timestamp = timestamp
    this.metricType = metricType
    this.value = value
    this.endpoint = endpoint
    this.tags = tags
  }
}

/**
 * models.go `eventBatch`: the wire payload for POST /api/v1/events and POST /api/v1/metrics,
 * matching BatchTelemetryRequest. Both lists are always present (`[]` when empty), like the
 * reference's model_dump.
 */
public class EventBatch {
  public var projectId: String = ""
  public var events: List<SecurityEvent>? = null
  public var metrics: List<SecurityMetric>? = null
  public var batchId: String = ""
  public var createdAt: Instant? = null
  public var compressed: Boolean = false
  public var agentVersion: String = ""
  public var guardVersion: String? = null
  public var guardCoreVersion: String? = null
}

/**
 * models.go `agentStatusPayload`: the wire payload for POST /api/v1/status, matching
 * AgentStatusRequest.
 */
public class AgentStatusPayload {
  public var timestamp: Instant? = null
  public var status: String = ""
  public var uptime: Double = 0.0
  public var eventsSent: Long = 0
  public var eventsFailed: Long = 0
  public var bufferSize: Int = 0
  public var lastFlush: Instant? = null
  public var errors: List<String>? = null
}

/**
 * transport.go `encryptedEnvelope`: the wire payload for POST /api/v1/events/encrypted. Only the
 * events/metrics arrays travel inside the ciphertext; batch_id and the version fields stay in
 * clear.
 */
internal class EncryptedEnvelope {
  var encryptedPayload: String = ""
  var batchId: String = ""
  var agentVersion: String = ""
  var guardVersion: String? = null
  var guardCoreVersion: String? = null
}

// -------------------------------------------------------- wire struct writers --

internal fun writeSecurityEventJson(
    sb: StringBuilder,
    ev: SecurityEvent,
) {
  sb.append('{')
  var first = true
  fun field(name: String, write: () -> Unit) {
    if (!first) {
      sb.append(',')
    }
    first = false
    appendGoString(sb, name)
    sb.append(':')
    write()
  }
  fun writeString(name: String, v: String?) {
    if (!v.isNullOrEmpty()) {
      field(name) { appendGoString(sb, v) }
    }
  }
  // ip_address, action_taken, reason and metadata are always present, as in the reference
  // (str defaults "" and dict default {}); optional fields the reference sends as null are omitted
  // when unset, which the API treats the same.
  fun writeRequiredString(name: String, v: String?) {
    field(name) { appendGoString(sb, v ?: "") }
  }
  // timestamp and event_type carry no omitempty.
  field("timestamp") {
    appendGoString(sb, rfc3339Nano(ev.timestamp ?: Instant.EPOCH))
  }
  field("event_type") { appendGoString(sb, ev.eventType) }
  writeString("idempotency_key", ev.idempotencyKey)
  writeRequiredString("ip_address", ev.ipAddress)
  writeString("country", ev.country)
  writeString("user_agent", ev.userAgent)
  writeRequiredString("action_taken", ev.actionTaken)
  writeRequiredString("reason", ev.reason)
  writeString("endpoint", ev.endpoint)
  writeString("method", ev.method)
  field("status_code") { sb.append(ev.statusCode?.toString() ?: "null") }
  field("response_time") { sb.append(ev.responseTime?.let { GoFloat.goJson(it) } ?: "null") }
  writeString("decorator_type", ev.decoratorType)
  writeString("rule_type", ev.ruleType)
  writeString("pattern_matched", ev.patternMatched)
  writeString("handler_name", ev.handlerName)
  field("metadata") { writeGoValue(sb, ev.metadata ?: emptyMap<String, Any?>()) }
  sb.append('}')
}

internal fun writeSecurityMetricJson(
    sb: StringBuilder,
    m: SecurityMetric,
) {
  sb.append('{')
  sb.append("\"timestamp\":")
  appendGoString(sb, rfc3339Nano(m.timestamp ?: Instant.EPOCH))
  sb.append(",\"metric_type\":")
  appendGoString(sb, m.metricType)
  sb.append(",\"value\":")
  sb.append(GoFloat.goJson(m.value))
  val endpoint = m.endpoint
  if (!endpoint.isNullOrEmpty()) {
    sb.append(",\"endpoint\":")
    appendGoString(sb, endpoint)
  }
  sb.append(",\"tags\":")
  writeGoValue(sb, m.tags ?: emptyMap<String, String>())
  sb.append('}')
}

internal fun writeEventBatchJson(
    sb: StringBuilder,
    batch: EventBatch,
) {
  sb.append("{\"project_id\":")
  appendGoString(sb, batch.projectId)
  sb.append(",\"events\":[")
  batch.events.orEmpty().forEachIndexed { i, ev ->
    if (i > 0) {
      sb.append(',')
    }
    writeSecurityEventJson(sb, ev)
  }
  sb.append("],\"metrics\":[")
  batch.metrics.orEmpty().forEachIndexed { i, m ->
    if (i > 0) {
      sb.append(',')
    }
    writeSecurityMetricJson(sb, m)
  }
  sb.append(']')
  sb.append(",\"batch_id\":")
  appendGoString(sb, batch.batchId)
  sb.append(",\"created_at\":")
  appendGoString(sb, rfc3339Nano(batch.createdAt ?: Instant.EPOCH))
  sb.append(",\"compressed\":")
  sb.append(if (batch.compressed) "true" else "false")
  sb.append(",\"agent_version\":")
  appendGoString(sb, batch.agentVersion)
  val guardVersion = batch.guardVersion
  if (!guardVersion.isNullOrEmpty()) {
    sb.append(",\"guard_version\":")
    appendGoString(sb, guardVersion)
  }
  val guardCoreVersion = batch.guardCoreVersion
  if (!guardCoreVersion.isNullOrEmpty()) {
    sb.append(",\"guard_core_version\":")
    appendGoString(sb, guardCoreVersion)
  }
  sb.append('}')
}

internal fun writeAgentStatusJson(
    sb: StringBuilder,
    payload: AgentStatusPayload,
) {
  sb.append("{\"timestamp\":")
  appendGoString(sb, rfc3339Nano(payload.timestamp ?: Instant.EPOCH))
  sb.append(",\"status\":")
  appendGoString(sb, payload.status)
  sb.append(",\"uptime\":")
  sb.append(GoFloat.goJson(payload.uptime))
  sb.append(",\"events_sent\":")
  sb.append(payload.eventsSent.toString())
  sb.append(",\"events_failed\":")
  sb.append(payload.eventsFailed.toString())
  sb.append(",\"buffer_size\":")
  sb.append(payload.bufferSize.toString())
  val lastFlush = payload.lastFlush
  sb.append(",\"last_flush\":")
  if (lastFlush != null) {
    appendGoString(sb, rfc3339Nano(lastFlush))
  } else {
    sb.append("null")
  }
  sb.append(",\"errors\":[")
  payload.errors.orEmpty().forEachIndexed { i, e ->
    if (i > 0) {
      sb.append(',')
    }
    appendGoString(sb, e)
  }
  sb.append(']')
  sb.append('}')
}

internal fun writeEncryptedEnvelopeJson(
    sb: StringBuilder,
    envelope: EncryptedEnvelope,
) {
  sb.append("{\"encrypted_payload\":")
  appendGoString(sb, envelope.encryptedPayload)
  sb.append(",\"batch_id\":")
  appendGoString(sb, envelope.batchId)
  sb.append(",\"agent_version\":")
  appendGoString(sb, envelope.agentVersion)
  val guardVersion = envelope.guardVersion
  if (!guardVersion.isNullOrEmpty()) {
    sb.append(",\"guard_version\":")
    appendGoString(sb, guardVersion)
  }
  val guardCoreVersion = envelope.guardCoreVersion
  if (!guardCoreVersion.isNullOrEmpty()) {
    sb.append(",\"guard_core_version\":")
    appendGoString(sb, guardCoreVersion)
  }
  sb.append('}')
}

// ------------------------------------------------------------------ readers --

/** Decoded timestamps accept RFC3339 with any offset, like encoding/json. */
internal fun parseInstant(raw: String): Instant? =
    try {
      Instant.parse(raw)
    } catch (e: Exception) {
      try {
        java.time.OffsetDateTime.parse(raw).toInstant()
      } catch (e2: Exception) {
        throw GoJsonException("cannot unmarshal timestamp: $raw")
      }
    }

private fun Any?.asString(): String? = this as? String

private fun Any?.asDouble(): Double =
    when (this) {
      is Double -> this
      is Long -> this.toDouble()
      is JsonNumber -> raw.toDoubleOrNull() ?: 0.0
      else -> 0.0
    }

private fun Any?.asInt(): Int? = asDouble().toInt()

/**
 * encoding/json Unmarshal into SecurityEvent: absent fields keep their zero values, extra fields
 * are ignored, "" strings decode as-is (sendEvent and the writers treat empty like absent,
 * mirroring omitempty).
 */
internal fun securityEventFromMap(map: Map<String, Any?>): SecurityEvent {
  val ev = SecurityEvent()
  (map["timestamp"] as? String)?.let { ev.timestamp = parseInstant(it) }
  (map["event_type"] as? String)?.let { ev.eventType = it }
  (map["idempotency_key"] as? String)?.let { ev.idempotencyKey = it }
  (map["ip_address"] as? String)?.let { ev.ipAddress = it }
  (map["country"] as? String)?.let { ev.country = it }
  (map["user_agent"] as? String)?.let { ev.userAgent = it }
  (map["action_taken"] as? String)?.let { ev.actionTaken = it }
  (map["reason"] as? String)?.let { ev.reason = it }
  (map["endpoint"] as? String)?.let { ev.endpoint = it }
  (map["method"] as? String)?.let { ev.method = it }
  (map["status_code"])?.let { ev.statusCode = it.asInt() }
  (map["response_time"])?.let { ev.responseTime = it.asDouble() }
  (map["decorator_type"] as? String)?.let { ev.decoratorType = it }
  (map["rule_type"] as? String)?.let { ev.ruleType = it }
  (map["pattern_matched"] as? String)?.let { ev.patternMatched = it }
  (map["handler_name"] as? String)?.let { ev.handlerName = it }
  (map["metadata"] as? Map<*, *>)?.let { md ->
    val converted = LinkedHashMap<String, Any?>()
    for ((k, v) in md) {
      converted[k.toString()] = v
    }
    ev.metadata = converted
  }
  return ev
}

internal fun securityMetricFromMap(map: Map<String, Any?>): SecurityMetric {
  val m = SecurityMetric()
  (map["timestamp"] as? String)?.let { m.timestamp = parseInstant(it) }
  (map["metric_type"] as? String)?.let { m.metricType = it }
  map["value"]?.let { m.value = it.asDouble() }
  (map["endpoint"] as? String)?.let { m.endpoint = it }
  (map["tags"] as? Map<*, *>)?.let { tags ->
    val converted = LinkedHashMap<String, String>()
    for ((k, v) in tags) {
      converted[k.toString()] = v?.toString() ?: ""
    }
    m.tags = converted
  }
  return m
}

internal fun securityEventFromJson(bytes: ByteArray): SecurityEvent {
  val parsed = parseJson(bytes, useNumber = false)
  return securityEventFromMap(
      parsed as? Map<String, Any?> ?: throw GoJsonException("cannot unmarshal event"),
  )
}

internal fun securityMetricFromJson(bytes: ByteArray): SecurityMetric {
  val parsed = parseJson(bytes, useNumber = false)
  return securityMetricFromMap(
      parsed as? Map<String, Any?> ?: throw GoJsonException("cannot unmarshal metric"),
  )
}

// -------------------------------------------------------------- identifiers --

/**
 * models.go `uuidFallbackCounter`: keeps generated identifiers unique if the entropy source ever
 * fails, so identifier generation can never throw or return "".
 */
private val uuidFallbackCounter = AtomicLong(0)

/**
 * models.go `cryptoRandRead`: the entropy source for identifiers and encryption nonces. It is a var
 * so tests can exercise the fail-open fallback paths deterministically; production code always
 * fills from SecureRandom.
 */
internal var cryptoRandRead: (ByteArray) -> Unit = { bytes ->
  SecureRandom().nextBytes(bytes)
}

/** models.go `newUUID4`: a random RFC 4122 version 4 UUID string. */
public fun newUUID4(): String {
  val b = ByteArray(16)
  try {
    cryptoRandRead(b)
  } catch (e: Exception) {
    val now = System.nanoTime()
    for (i in 0 until 8) {
      b[i] = (now ushr ((7 - i) * 8)).toByte()
    }
    val counter = uuidFallbackCounter.incrementAndGet()
    for (i in 0 until 8) {
      b[8 + i] = (counter ushr ((7 - i) * 8)).toByte()
    }
  }
  b[6] = ((b[6].toInt() and 0x0f) or 0x40).toByte()
  b[8] = ((b[8].toInt() and 0x3f) or 0x80.toByte().toInt()).toByte()
  fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
  return (hex(b.copyOfRange(0, 4)) +
      "-" +
      hex(b.copyOfRange(4, 6)) +
      "-" +
      hex(b.copyOfRange(6, 8)) +
      "-" +
      hex(b.copyOfRange(8, 10)) +
      "-" +
      hex(b.copyOfRange(10, 16)))
}

/** models.go `randomHex`: n random bytes as hex. */
internal fun randomHex(n: Int): String {
  val buf = ByteArray(n)
  return try {
    cryptoRandRead(buf)
    buf.joinToString("") { "%02x".format(it) }
  } catch (e: Exception) {
    String.format("%0" + (n * 2) + "x", uuidFallbackCounter.incrementAndGet())
  }
}

/**
 * models.go `newBatchID`: "{unix_millis}-{8 hex chars}", generated once per batch attempt group so
 * retries and 413 splits of the same batch stay idempotent-friendly.
 */
public fun newBatchID(): String = System.currentTimeMillis().toString() + "-" + randomHex(4)
