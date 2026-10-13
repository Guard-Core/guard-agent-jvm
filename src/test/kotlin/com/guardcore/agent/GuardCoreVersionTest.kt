package com.guardcore.agent

import com.guardcore.engine.GuardCoreEngine
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Runtime detection of the guard-core-jvm engine version (agent.go guardCoreVersionFromBuildInfo).
 */
class GuardCoreVersionTest {
  private fun agentWith(version: String): GuardAgent =
      newTestAgent(tempDirFor("gcv"), null, AgentOptions().withLogger(quietLogger())) {
        it.guardCoreVersion = version
      }

  @Test
  fun emptyConfigGetsEngineVersion() {
    val agent = agentWith("")
    assertEquals(GuardCoreEngine.VERSION, agent.cfg.guardCoreVersion)
    assertEquals(GuardCoreEngine.VERSION, detectGuardCoreVersion(GuardAgent.ENGINE_CLASS_NAME))
  }

  @Test
  fun userSetVersionWins() {
    val agent = agentWith("9.9.9")
    assertEquals("9.9.9", agent.cfg.guardCoreVersion)
  }

  @Test
  fun missingClassYieldsEmpty() {
    assertEquals("", detectGuardCoreVersion("com.example.DoesNotExist"))
  }
}
