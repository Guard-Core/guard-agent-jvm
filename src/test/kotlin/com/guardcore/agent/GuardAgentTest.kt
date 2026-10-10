package com.guardcore.agent

import kotlin.test.Test
import kotlin.test.assertEquals

class GuardAgentTest {

  @Test
  fun versionMatchesSnapshotLine() {
    assertEquals("3.2.2", GuardAgent.VERSION)
  }
}
