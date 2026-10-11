package com.guardcore.agent

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Port of guard-agent-go `models_test.go`. */
class ModelsTest {
  private val uuid4Pattern =
      Regex("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

  private val batchIDPattern = Regex("^[0-9]+-[0-9a-f]{8}$")

  @Test
  fun newUUID4Shape() {
    val seen = HashSet<String>()
    repeat(100) {
      val id = newUUID4()
      assertTrue(uuid4Pattern.matches(id), "uuid $id does not match the v4 shape")
      seen.add(id)
    }
    assertEquals(100, seen.size, "expected 100 unique ids")
  }

  @Test
  fun newBatchIDShape() {
    val id = newBatchID()
    assertTrue(batchIDPattern.matches(id), "batch id $id must look like {unix_millis}-{8 hex}")
  }

  @Test
  fun validMetricType() {
    for (mt in
        listOf(
            MetricTypes.REQUEST_COUNT,
            MetricTypes.RESPONSE_TIME,
            MetricTypes.ERROR_RATE,
            MetricTypes.BANDWIDTH_USAGE,
            MetricTypes.THREAT_LEVEL,
            MetricTypes.BLOCK_RATE,
            MetricTypes.CACHE_HIT_RATE,
        )) {
      assertTrue(MetricTypes.isValid(mt), "metric type $mt must be valid")
    }
    assertFalse(MetricTypes.isValid("bogus"), "bogus metric type must be invalid")
  }

  @Test
  fun statusConstants() {
    assertEquals("healthy", AgentStatusValues.HEALTHY)
    assertEquals("degraded", AgentStatusValues.DEGRADED)
    assertEquals("failed", AgentStatusValues.FAILED)
  }
}
