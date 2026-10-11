package com.guardcore.agent

/**
 * Port of guard-agent-go `redact.go`: telemetry redaction. Map keys are matched case-insensitively
 * after stripping whitespace; JSON-looking string values are scanned and re-serialized; oversized
 * or over-deep subtrees are redacted wholesale (fail-closed), all mirroring guard_agent.utils.
 */

/** The default sensitive-header set (guard_agent AgentConfig.sensitive_headers). */
public val DEFAULT_SENSITIVE_HEADERS: List<String> =
    listOf(
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
    )

/**
 * redact.go `maxSanitizeDepth`: bounds recursion; a subtree deeper than this is redacted wholesale
 * rather than walked.
 */
internal const val MAX_SANITIZE_DEPTH: Int = 10

/**
 * redact.go `maxJSONScanLen`: bounds how long a string is JSON-scanned; longer strings are redacted
 * wholesale (fail-closed).
 */
internal const val MAX_JSON_SCAN_LEN: Int = 8192

/** The sentinel replacing every sensitive value. */
public const val REDACTED_MARKER: String = "[REDACTED]"

/**
 * redact.go `normalizeSensitiveHeaders`: lowercases and trims the configured header names and
 * returns the defaults for a null list. An empty non-null list is an intentional replacement:
 * nothing beyond it is redacted.
 */
public fun normalizeSensitiveHeaders(headers: List<String>?): List<String> {
  val source = headers ?: DEFAULT_SENSITIVE_HEADERS
  return source.map { it.trim().lowercase() }
}

private fun isSensitiveKey(
    key: String,
    loweredSensitive: Set<String>,
): Boolean = key.trim().lowercase() in loweredSensitive

/**
 * redact.go `SanitizeHeaders`: removes sensitive values from telemetry data. It recurses into
 * nested maps, lists, and JSON-looking string values up to a bounded depth; a subtree deeper than
 * that is redacted wholesale rather than walked. Values of unrepresentable kinds are redacted
 * fail-closed.
 */
public fun sanitizeHeaders(
    value: Any?,
    sensitiveHeaders: List<String>?,
): Any? {
  val lowered: Set<String> =
      (sensitiveHeaders ?: DEFAULT_SENSITIVE_HEADERS).map { it.trim().lowercase() }.toSet()
  return sanitizeValue(value, lowered, 0)
}

private fun sanitizeValue(
    value: Any?,
    loweredSensitive: Set<String>,
    depth: Int,
): Any? {
  if (depth > MAX_SANITIZE_DEPTH) {
    return REDACTED_MARKER
  }
  return when (value) {
    null,
    is Boolean,
    is Int,
    is Long,
    is Short,
    is Byte,
    is Double,
    is Float,
    is ByteArray,
    -> value
    is String -> sanitizeStringValue(value, loweredSensitive, depth)
    is JsonNumber -> value
    is Map<*, *> -> sanitizeMap(value, loweredSensitive, depth)
    is List<*> -> value.map { sanitizeValue(it, loweredSensitive, depth + 1) }
    else -> REDACTED_MARKER
  }
}

private fun sanitizeMap(
    value: Map<*, *>,
    loweredSensitive: Set<String>,
    depth: Int,
): Any? {
  val sanitized = LinkedHashMap<Any?, Any?>()
  for ((key, item) in value) {
    val keyString = key?.toString() ?: "null"
    if (isSensitiveKey(keyString, loweredSensitive)) {
      sanitized[key] = REDACTED_MARKER
      continue
    }
    sanitized[key] = sanitizeValue(item, loweredSensitive, depth + 1)
  }
  return sanitized
}

/**
 * redact.go `sanitizeStringValue`: JSON-scans strings that look like JSON (leading `{`, `[`, or
 * `"`), redacts the scan when the candidate exceeds maxJSONScanLen, and re-serializes the sanitized
 * structure; a value that does not parse as JSON passes through untouched.
 */
private fun sanitizeStringValue(
    value: String,
    loweredSensitive: Set<String>,
    depth: Int,
): String {
  val stripped = value.trim()
  if (stripped.isEmpty() || (stripped[0] != '{' && stripped[0] != '[' && stripped[0] != '"')) {
    return value
  }
  if (stripped.length > MAX_JSON_SCAN_LEN) {
    return REDACTED_MARKER
  }
  val parsed =
      try {
        parseJson(stripped, useNumber = false)
      } catch (e: Exception) {
        return value
      }
  val sanitized = sanitizeValue(parsed, loweredSensitive, depth + 1)
  return try {
    goJson(sanitized).toString(Charsets.UTF_8)
  } catch (e: Exception) {
    REDACTED_MARKER
  }
}

/**
 * redact.go `redactEventMetadata`: a copy of the event with a redacted Metadata map. The input map
 * is never mutated.
 */
internal fun redactEventMetadata(
    ev: SecurityEvent,
    sensitiveHeaders: List<String>?,
): SecurityEvent {
  if (ev.metadata == null) {
    return ev
  }
  val copy = ev.copy()
  @Suppress("UNCHECKED_CAST")
  copy.metadata = sanitizeHeaders(ev.metadata, sensitiveHeaders) as? Map<String, Any?>
  return copy
}

/** redact.go `redactMetricTags`: a copy of the metric with redacted Tags. */
internal fun redactMetricTags(
    m: SecurityMetric,
    sensitiveHeaders: List<String>?,
): SecurityMetric {
  if (m.tags == null) {
    return m
  }
  val copy = SecurityMetric(m.timestamp, m.metricType, m.value, m.endpoint, null)
  @Suppress("UNCHECKED_CAST")
  val sanitized = sanitizeHeaders(m.tags, sensitiveHeaders) as? Map<Any?, Any?>
  val tags = LinkedHashMap<String, String>()
  sanitized?.forEach { (k, v) -> tags[k?.toString() ?: "null"] = v?.toString() ?: "" }
  copy.tags = tags
  return copy
}

/**
 * redact.go `redactBatch`: the serialization-time redaction pass the Python transport runs over
 * every outgoing batch body.
 */
internal fun redactBatch(
    batch: EventBatch,
    sensitiveHeaders: List<String>?,
) {
  batch.events = batch.events?.map { redactEventMetadata(it, sensitiveHeaders) }
  batch.metrics = batch.metrics?.map { redactMetricTags(it, sensitiveHeaders) }
}
