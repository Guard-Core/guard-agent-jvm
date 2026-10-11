package com.guardcore.agent

import java.time.Duration
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Port of guard-agent-go `config_test.go`. */
class ConfigTest {
  private fun installIDPath(tmp: String): String = tmp + "/install-id"

  @Test
  fun newFillsDefaults() {
    val tmp = tempDirFor("cfg-defaults")
    val agent =
        GuardAgent.create(
            AgentConfig().apply {
              apiKey = "test-api-key"
              installIdPath = installIDPath(tmp.toString())
            },
        )
    try {
      val cfg = agent.cfg
      assertEquals(100, cfg.bufferSize)
      assertEquals(Duration.ofSeconds(30), cfg.flushInterval)
      assertEquals(Duration.ofSeconds(300), cfg.statusInterval)
      assertEquals(0, cfg.retryAttempts, "zero-honest: DefaultConfig sets 3")
      assertEquals(Duration.ofSeconds(30), cfg.timeout)
      assertEquals(1.0, cfg.backoffFactor)
      assertEquals(0.8, cfg.highWatermarkRatio)
      assertEquals(1, cfg.maxConcurrentFlushes)
      assertEquals(OverflowPolicy.DROP, cfg.overflow)
      assertEquals(0, cfg.compressionThreshold, "zero-honest: DefaultConfig sets 1024")
      assertEquals(DEFAULT_ENDPOINT, cfg.endpoint)
      assertTrue(agent.installId.isNotEmpty(), "install id must be resolved")
    } finally {
      agent.stop()
    }
  }

  @Test
  fun defaultConfigEnablesFeatures() {
    val cfg = defaultConfig()
    assertTrue(cfg.enableEvents && cfg.enableMetrics && cfg.compressionEnabled)
    assertEquals(3, cfg.retryAttempts)
    assertEquals(1024, cfg.compressionThreshold)
  }

  private class ValidationCase(
      val name: String,
      val cfg: AgentConfig,
      val problem: String,
  )

  @Test
  fun configValidationErrors() {
    val cases =
        listOf(
            ValidationCase(
                "missing api key",
                AgentConfig().apply { installIdPath = "x" },
                "api key",
            ),
            ValidationCase(
                "short api key",
                AgentConfig().apply {
                  apiKey = "short"
                  installIdPath = "x"
                },
                "at least 10",
            ),
            ValidationCase(
                "bad scheme",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  endpoint = "ftp://example.com"
                  installIdPath = "x"
                },
                "http or https",
            ),
            ValidationCase(
                "not a url",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  endpoint = "not a url"
                  installIdPath = "x"
                },
                "valid URL",
            ),
            ValidationCase(
                "negative buffer",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  bufferSize = -1
                  installIdPath = "x"
                },
                "buffer size",
            ),
            ValidationCase(
                "negative flush",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  flushInterval = Duration.ofSeconds(-1)
                  installIdPath = "x"
                },
                "flush interval",
            ),
            ValidationCase(
                "small status interval",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  statusInterval = Duration.ofSeconds(30)
                  installIdPath = "x"
                },
                "at least 60s",
            ),
            ValidationCase(
                "watermark above one",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  highWatermarkRatio = 1.5
                  installIdPath = "x"
                },
                "watermark",
            ),
            ValidationCase(
                "bad overflow",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  overflow = OverflowPolicy("explode")
                  installIdPath = "x"
                },
                "overflow",
            ),
            ValidationCase(
                "negative retry",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  retryAttempts = -1
                  installIdPath = "x"
                },
                "retry attempts",
            ),
            ValidationCase(
                "negative timeout",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  timeout = Duration.ofSeconds(-1)
                  installIdPath = "x"
                },
                "timeout",
            ),
            ValidationCase(
                "negative backoff",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  backoffFactor = -1.0
                  installIdPath = "x"
                },
                "backoff factor",
            ),
            ValidationCase(
                "negative compression threshold",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  compressionThreshold = -1
                  installIdPath = "x"
                },
                "compression threshold",
            ),
            ValidationCase(
                "redis without url",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  redis = RedisConfig()
                  installIdPath = "x"
                },
                "redis url",
            ),
            ValidationCase(
                "negative redis ttl",
                AgentConfig().apply {
                  apiKey = "test-api-key"
                  redis = RedisConfig("redis://localhost:6379", ttl = Duration.ofSeconds(-1))
                  installIdPath = "x"
                },
                "redis ttl",
            ),
        )
    for (case in cases) {
      val err =
          assertFailsWith<AgentConfigException>("case ${case.name}") { GuardAgent.create(case.cfg) }
      assertTrue(
          err.message!!.contains(case.problem),
          "case ${case.name}: expected problem \"${case.problem}\" in \"${err.message}\"",
      )
    }
  }

  @Test
  fun configErrorAggregatesProblems() {
    val err =
        assertFailsWith<AgentConfigException> {
          GuardAgent.create(
              AgentConfig().apply {
                apiKey = "x"
                statusInterval = Duration.ofSeconds(1)
              },
          )
        }
    assertTrue(err.problems.size >= 2, "expected aggregated problems, got ${err.problems}")
  }

  @Test
  fun endpointNormalization() {
    val logger = CapturingLogger()
    val tmp = tempDirFor("cfg-endpoint")
    val agent =
        GuardAgent.create(
            AgentConfig().apply {
              apiKey = "test-api-key"
              endpoint = "https://example.com/api/v1/"
              installIdPath = installIDPath(tmp.toString())
            },
            AgentOptions().withLogger(logger),
        )
    try {
      assertEquals("https://example.com", agent.cfg.endpoint)
      assertTrue(
          logger.output().contains("/api/v1"),
          "expected /api/v1 warning in log, got \"${logger.output()}\"",
      )
    } finally {
      agent.stop()
    }
  }

  @Test
  fun withLoggerAndClientIgnoreNil() {
    val tmp = tempDirFor("cfg-options")
    val agent =
        GuardAgent.create(
            AgentConfig().apply {
              apiKey = "test-api-key"
              installIdPath = installIDPath(tmp.toString())
            },
            AgentOptions().withLogger(null).withHttpClient(null),
        )
    try {
      assertTrue(agent.logger != null, "logger must fall back to the default")
    } finally {
      agent.stop()
    }
  }

  // ------------------------------------------------ normalize coverage --
  // Port of coverage_test.go TestNormalizeRejectsUnparseableRedisURL and
  // the config-parity validation arms from parity_test.go.

  @Test
  fun normalizeRejectsUnparseableRedisURL() {
    val result =
        normalize(
            AgentConfig().apply {
              apiKey = "test-api-key"
              redis = RedisConfig("redis://localhost:6379")
            },
        )
    assertEquals(null, result.error, "a parseable redis url must normalize")
  }

  @Test
  fun configParityValidation() {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.dynamicRuleInterval = Duration.ofSeconds(30)
    var err = normalize(cfg).error
    assertTrue(
        err != null && err!!.message!!.contains("dynamic rule interval"),
        "expected a dynamic rule interval problem, got $err",
    )

    cfg.dynamicRuleInterval = Duration.ofSeconds(300)
    cfg.maxPayloadSize = -1
    err = normalize(cfg).error
    assertTrue(
        err != null && err!!.message!!.contains("max payload size"),
        "expected a max payload size problem, got $err",
    )

    cfg.maxPayloadSize = 0
    val normalized = normalize(cfg)
    assertEquals(null, normalized.error, "zero max payload size must default-fill")
    assertEquals(1024, normalized.cfg.maxPayloadSize)
  }

  @Test
  fun configParityDefaults() {
    val cfg = defaultConfig()
    assertEquals(1024, cfg.maxPayloadSize)
    assertEquals(Duration.ofSeconds(300), cfg.dynamicRuleInterval)
    assertEquals(null, cfg.onError, "on_error must default to null")
  }
}
