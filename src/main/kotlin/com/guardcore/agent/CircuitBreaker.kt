package com.guardcore.agent

import java.time.Duration
import java.time.Instant

/**
 * Port of guard-agent-go `circuit_breaker.go`: a consecutive-failure breaker guarding the
 * transport, mirroring guard-agent (Python) transport.py: the breaker opens after 5 consecutive
 * failures and probes recovery after 60 seconds. Permanent rejections (4xx that carry a definitive
 * verdict) are exempt from failure counting.
 */
internal const val BREAKER_FAILURE_THRESHOLD: Int = 5
internal val BREAKER_RECOVERY_TIMEOUT: Duration = Duration.ofSeconds(60)

public enum class CircuitState(
    public val wire: String,
) {
  CLOSED("closed"),
  OPEN("open"),
  HALF_OPEN("half_open"),
}

public class CircuitBreaker(
    private val threshold: Int = BREAKER_FAILURE_THRESHOLD,
    private val recoveryTimeout: Duration = BREAKER_RECOVERY_TIMEOUT,
) {
  /** The clock seam (Go `now` field): tests pin time deterministically. */
  internal var now: () -> Instant = Instant::now

  private val lock = Any()
  private var state: CircuitState = CircuitState.CLOSED
  private var failureCount: Int = 0
  private var openedAt: Instant = Instant.EPOCH

  public constructor() : this(BREAKER_FAILURE_THRESHOLD, BREAKER_RECOVERY_TIMEOUT)

  /**
   * circuit_breaker.go `Admit`: reports whether a call may proceed. While OPEN and inside the
   * recovery window it throws a [GuardAgentException] with kind [ErrorKind.CIRCUIT_OPEN].
   */
  public fun admit() {
    synchronized(lock) {
      when (state) {
        CircuitState.OPEN -> {
          if (Duration.between(openedAt, now()) >= recoveryTimeout) {
            state = CircuitState.HALF_OPEN
            return
          }
          throw GuardAgentException(Err.CIRCUIT_OPEN, ErrorKind.CIRCUIT_OPEN)
        }
        else -> return
      }
    }
  }

  /** circuit_breaker.go `Success`: the breaker closes and the failure count resets. */
  public fun success() {
    synchronized(lock) {
      state = CircuitState.CLOSED
      failureCount = 0
    }
  }

  /**
   * circuit_breaker.go `Failure`: records a retryable failure. Permanent rejections must not be
   * reported here. Reaching the threshold, or failing while HALF_OPEN, opens the breaker.
   */
  public fun failure() {
    synchronized(lock) {
      failureCount++
      if (state == CircuitState.HALF_OPEN || failureCount >= threshold) {
        state = CircuitState.OPEN
        openedAt = now()
      }
    }
  }

  /** circuit_breaker.go `Open`: whether the breaker currently rejects calls. */
  public fun open(): Boolean {
    synchronized(lock) {
      return state == CircuitState.OPEN
    }
  }

  /** circuit_breaker.go `State`: "closed", "open", or "half_open". */
  public fun state(): String {
    synchronized(lock) {
      return state.wire
    }
  }
}
