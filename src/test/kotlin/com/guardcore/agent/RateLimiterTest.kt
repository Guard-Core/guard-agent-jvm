package com.guardcore.agent

import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Port of guard-agent-go `parity_test.go` rate limiter units. */
class RateLimiterTest {
  @Test
  fun rateLimiterAdmitsUpToCap() {
    val limiter = RateLimiter(3, Duration.ofSeconds(1))
    repeat(3) { i ->
      assertTrue(limiter.acquire(), "acquire ${i + 1} must be admitted")
    }
    assertEquals(false, limiter.acquire(), "4th acquire within the window must be denied")
    val wait = limiter.retryAfter()
    assertTrue(
        !wait.isZero && wait <= Duration.ofSeconds(1),
        "retry after got $wait want within (0, 1s]",
    )
  }

  @Test
  fun rateLimiterWindowPrunes() {
    val limiter = RateLimiter(1, Duration.ofMillis(10))
    assertTrue(limiter.acquire(), "first acquire must be admitted")
    assertEquals(false, limiter.acquire(), "second acquire must be denied")
    Thread.sleep(20)
    assertTrue(limiter.acquire(), "acquire after the window must be admitted")
  }

  @Test
  fun rateLimiterRetryAfterZeroWhenEmpty() {
    val limiter = RateLimiter(1, Duration.ofSeconds(1))
    assertEquals(
        Duration.ZERO,
        limiter.retryAfter(),
        "retry after got ${limiter.retryAfter()} want 0",
    )
  }
}
