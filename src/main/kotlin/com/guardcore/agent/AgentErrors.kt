package com.guardcore.agent

import java.time.Duration

/**
 * Port of guard-agent-go `errors.go`: typed errors. Go callers test with errors.Is for the
 * sentinels and errors.As for the structural types; the JVM idiom carries the sentinel as a
 * [GuardAgentException.Kind] on the exception itself, matched with [matchesKind] (which walks
 * joined causes like errors.Is walks wrapped chains).
 *
 * [ErrBufferFull] is the sentinel matched by every [BufferFullError] via errors.Is.
 * [BufferFullError] itself is returned by sendEvent and sendMetric only when the configured
 * overflow policy is [OverflowPolicy.RAISE].
 */
public enum class ErrorKind {
  BUFFER_FULL,
  CLOSED,
  CIRCUIT_OPEN,
  INVALID_EVENT,
  INTERNAL,
  CONTEXT_DONE,
}

/** The sentinel vocabulary, matching the Go package-level error values. */
public object Err {
  /** errors.go `ErrBufferFull`. */
  public const val BUFFER_FULL: String = "guardagent: buffer full"

  /** errors.go `ErrClosed`, returned by sendEvent, sendMetric, and flush after stop. */
  public const val CLOSED: String = "guardagent: agent is stopped"

  /** errors.go `ErrCircuitOpen`, returned by flush while the transport breaker is open. */
  public const val CIRCUIT_OPEN: String = "guardagent: transport circuit breaker is open"

  /** errors.go `ErrInvalidEvent`, wrapping the item-specific detail. */
  public const val INVALID_EVENT: String = "guardagent: invalid telemetry item"

  /** errors.go `ErrInternal`, returned when an exported method recovered from a panic. */
  public const val INTERNAL: String = "guardagent: internal error"
}

/**
 * Base type for the sentinel-kind failures (closed, circuit open, invalid item, internal).
 * Structural types ([BufferFullError], [PermanentError], [RateLimitedError]) are their own classes
 * exactly like the Go structs.
 */
public open class GuardAgentException(
    message: String,
    public val errorKind: ErrorKind,
) : RuntimeException(message)

/**
 * errors.go `BufferFullError`: the per-kind buffer is full under the OverflowRaise policy. Matches
 * [ErrorKind.BUFFER_FULL].
 */
public class BufferFullError(
    /** "event" or "metric". */
    public val kind: String,
    public val maxLen: Int,
) :
    GuardAgentException(
        "guardagent: $kind buffer full at maxlen=$maxLen and overflow policy is raise",
        ErrorKind.BUFFER_FULL,
    )

/**
 * errors.go `ConfigError`: one or more invalid configuration fields. The message joins every
 * problem with "; ".
 */
public class AgentConfigException(
    public val problems: List<String>,
) : RuntimeException("guardagent: invalid configuration: " + problems.joinToString("; "))

/**
 * errors.go `PermanentError`: a non-retryable HTTP rejection from the ingestion API (400, 404,
 * 422). The affected batch is durably dropped (persisted records confirmed), never requeued.
 */
public class PermanentError(
    public val statusCode: Int,
    public val detail: String,
) : RuntimeException("guardagent: permanent rejection with status $statusCode: $detail")

/**
 * errors.go `RateLimitedError`: the ingestion API answered 429 and the Retry-After budget was
 * exhausted without a successful retry. The affected batch is requeued.
 */
public class RateLimitedError(
    public val retryAfter: Duration,
) :
    RuntimeException(
        "guardagent: rate limited, retry after " + retryAfter.seconds.toString() + "s",
    )

/**
 * errors.go `payloadTooLargeError`: marks a 413 response so sendBatch can recurse into the
 * split-or-drop path. It never escapes the package.
 */
internal class PayloadTooLargeError(
    detail: String,
) : RuntimeException("guardagent: payload too large: $detail")

/**
 * errors.go `errors.Join` analog: a flush reports the transport error of any failed kind; matching
 * walks every joined error.
 */
internal class JoinedErrors(
    public val errors: List<Throwable>,
) : RuntimeException(errors.joinToString("\n") { it.message ?: it::class.java.simpleName })

/** errors.Is analog: reports whether [this] or any joined/wrapped cause carries [targetKind]. */
public fun Throwable?.matchesKind(targetKind: ErrorKind): Boolean {
  var current: Throwable? = this
  val seen = HashSet<Throwable>()
  while (current != null && seen.add(current)) {
    if (current is GuardAgentException && current.errorKind == targetKind) {
      return true
    }
    if (current is JoinedErrors && current.errors.any { it.matchesKind(targetKind) }) {
      return true
    }
    current = current.cause
  }
  return false
}
