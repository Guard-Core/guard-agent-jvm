package com.guardcore.agent

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Port of guard-agent-go `circuit_breaker_test.go`. */
class CircuitBreakerTest {
  @Test
  fun circuitBreakerOpensAfterThreshold() {
    val cb = CircuitBreaker()
    val base = Instant.EPOCH
    var now = base
    cb.now = { now }
    repeat(BREAKER_FAILURE_THRESHOLD - 1) { cb.failure() }
    assertFalse(cb.open(), "breaker must stay closed below the threshold")
    cb.admit()
    cb.failure()
    assertTrue(cb.open(), "breaker must open at the threshold")
    val err = assertFailsWith<GuardAgentException> { cb.admit() }
    assertEquals(ErrorKind.CIRCUIT_OPEN, err.errorKind, "Admit while open must be ErrCircuitOpen")
  }

  @Test
  fun circuitBreakerHalfOpenThenRecovery() {
    val cb = CircuitBreaker()
    val base = Instant.EPOCH
    var now = base
    cb.now = { now }
    repeat(BREAKER_FAILURE_THRESHOLD) { cb.failure() }
    now = base.plus(BREAKER_RECOVERY_TIMEOUT)
    cb.admit()
    assertEquals("HALF_OPEN", cb.state(), "state after the recovery window")
    // A failure while half-open reopens the breaker with a fresh window.
    now = base.plus(BREAKER_RECOVERY_TIMEOUT).plusSeconds(1)
    cb.failure()
    assertTrue(cb.open(), "half-open failure must reopen the breaker")
    now = base.plus(BREAKER_RECOVERY_TIMEOUT.multipliedBy(2)).plusSeconds(1)
    cb.admit()
    cb.success()
    assertFalse(cb.open(), "success must close the breaker")
    assertEquals("CLOSED", cb.state())
  }

  @Test
  fun circuitBreakerSuccessResetsCount() {
    val cb = CircuitBreaker()
    repeat(BREAKER_FAILURE_THRESHOLD - 1) { cb.failure() }
    cb.success()
    repeat(BREAKER_FAILURE_THRESHOLD - 1) { cb.failure() }
    assertFalse(cb.open(), "success must reset the consecutive failure count")
  }
}
