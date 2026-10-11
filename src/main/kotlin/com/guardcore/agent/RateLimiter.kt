package com.guardcore.agent

import java.time.Duration
import java.time.Instant

/**
 * Port of guard-agent-go `rate_limiter.go`: a sliding-window rate limiter for the agent's outgoing
 * requests, mirroring guard_agent.utils.RateLimiter (100, 60) built in _transport_lifecycle. Every
 * request attempt must acquire a slot first; when the window is saturated the caller waits
 * [retryAfter] until the next slot frees up. It is safe for concurrent use.
 */
internal const val DEFAULT_LIMITER_MAX_CALLS: Int = 100
internal val DEFAULT_LIMITER_WINDOW: Duration = Duration.ofSeconds(60)

public class RateLimiter(
    private val maxCalls: Int,
    private val window: Duration,
) {
  private val lock = Any()
  private val calls = ArrayDeque<Instant>()

  public constructor() : this(DEFAULT_LIMITER_MAX_CALLS, DEFAULT_LIMITER_WINDOW)

  /**
   * rate_limiter.go `Acquire`: records one call when the limiter is under its cap and reports
   * whether the call is allowed.
   */
  public fun acquire(): Boolean {
    synchronized(lock) {
      val now = Instant.now()
      pruneLocked(now)
      if (calls.size < maxCalls) {
        calls.addLast(now)
        return true
      }
      return false
    }
  }

  /**
   * rate_limiter.go `RetryAfter`: how long until the next slot frees up; zero when the limiter
   * currently admits calls. It mirrors RateLimiter.get_retry_after.
   */
  public fun retryAfter(): Duration {
    synchronized(lock) {
      if (calls.isEmpty()) {
        return Duration.ZERO
      }
      val oldest = calls.first()
      val wait = window.minus(Duration.between(oldest, Instant.now()))
      if (wait.isNegative) {
        return Duration.ZERO
      }
      return wait
    }
  }

  internal fun windowMillisForTest(): Long = window.toMillis()

  /** Test seam for the Go tests' direct calls-slice manipulation. */
  internal fun seedCallsForTest(times: List<Instant>) {
    synchronized(lock) {
      calls.clear()
      for (t in times) {
        calls.addLast(t)
      }
    }
  }

  /**
   * rate_limiter.go `pruneLocked`: drops call timestamps that left the window. Calls are appended
   * in order, so the oldest is always first.
   */
  private fun pruneLocked(now: Instant) {
    while (calls.isNotEmpty() && Duration.between(calls.first(), now) >= window) {
      calls.removeFirst()
    }
  }
}
