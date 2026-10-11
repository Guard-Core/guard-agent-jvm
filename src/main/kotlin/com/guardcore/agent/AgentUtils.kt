package com.guardcore.agent

import java.security.MessageDigest

/**
 * Port of guard-agent-go `utils.go`: payload truncation, IP hashing, batch id generation, response
 * body summaries, safe JSON helpers, and the advisory config audit.
 */

/**
 * utils.go `TruncatePayload`: truncates payload to maxSize with a visible marker, mirroring
 * guard_agent.utils.truncate_payload. maxSize counts bytes (the Python original counts characters;
 * for ASCII telemetry the two agree).
 */
public fun truncatePayload(
    payload: String,
    maxSize: Int,
): String {
  if (payload.length <= maxSize) {
    return payload
  }
  return payload.substring(0, maxSize) + "...[TRUNCATED]"
}

/**
 * utils.go `HashIP`: hashes an IP address for privacy-conscious telemetry: the first 16 hex
 * characters of SHA-256 over ip+salt, mirroring guard_agent.utils.hash_ip.
 */
public fun hashIP(
    ip: String,
    salt: String,
): String {
  val digest = MessageDigest.getInstance("SHA-256").digest((ip + salt).toByteArray(Charsets.UTF_8))
  return digest.joinToString("") { "%02x".format(it) }.take(16)
}

/** utils.go `GenerateBatchID`: the reference generate_batch_id shape. */
public fun generateBatchID(): String = newBatchID()

/**
 * utils.go `SummarizeResponseBody`: collapses an HTTP response body into a bounded, single-line
 * summary: whitespace (including newlines) collapses so one response body can never span more than
 * one log line, and the summary caps at maxLength characters with the original length noted when
 * truncated.
 */
public fun summarizeResponseBody(
    text: String,
    maxLength: Int,
): String {
  val collapsed = text.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ")
  if (maxLength <= 0 || collapsed.length <= maxLength) {
    return collapsed
  }
  return collapsed.substring(0, maxLength) + "... [truncated, " + text.length + " chars total]"
}

/**
 * utils.go `SerializationError`: raised when an object cannot be serialized to JSON for transport.
 */
public class SerializationError(
    message: String,
) : RuntimeException(message)

/**
 * utils.go `SafeJSONSerialize`: serializes v to compact JSON, throwing [SerializationError] on
 * failure.
 */
public fun safeJSONSerialize(v: Any?): String =
    try {
      goJson(v).toString(Charsets.UTF_8)
    } catch (e: Exception) {
      throw SerializationError(e.message ?: e::class.java.simpleName)
    }

/**
 * utils.go `SafeJSONDeserialize`: deserializes a JSON object with error handling; a non-object
 * payload or a parse failure returns null.
 */
public fun safeJSONDeserialize(payload: String): Map<String, Any?>? =
    try {
      parseJson(payload, useNumber = false) as? Map<String, Any?>
    } catch (e: Exception) {
      null
    }

/**
 * utils.go `ValidateConfig`: audits an agent configuration and returns the list of problems: an
 * advisory surface that never mutates or applies defaults (the construction-time normalize applies
 * defaults and fails closed). An empty list means the configuration is sound.
 */
public fun validateConfig(cfg: AgentConfig): List<String> {
  val normalized = normalize(cfg)
  val problems = mutableListOf<String>()
  problems.addAll(normalized.problems)
  problems.addAll(normalized.warnings)
  return problems
}
