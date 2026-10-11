package com.guardcore.agent

import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path
import java.time.Duration
import java.util.logging.Logger

/**
 * Port of guard-agent-go `agent_test.go` helpers: the deterministic test agent construction, sample
 * telemetry, and the condition poller.
 */

/** agent_test.go `newTestAgent`. */
fun newTestAgent(
    tmpDir: Path,
    mock: MockIngest?,
    options: AgentOptions = AgentOptions(),
    mutate: ((AgentConfig) -> Unit)? = null,
): GuardAgent {
  val cfg = defaultConfig()
  cfg.apiKey = "test-api-key-123"
  if (mock != null) {
    cfg.endpoint = mock.url
  }
  cfg.flushInterval = Duration.ofHours(1)
  cfg.statusInterval = Duration.ofHours(1)
  cfg.installIdPath = tmpDir.resolve("install-id").toString()
  cfg.backoffFactor = 0.001
  mutate?.invoke(cfg)
  val agent = GuardAgent.create(cfg, options)
  return agent
}

/** agent_test.go `testEvent`. */
fun testEvent(
    n: Int,
    pad: String = "",
): SecurityEvent =
    SecurityEvent().apply {
      eventType = "event_$n"
      ipAddress = "203.0.113.7"
      metadata = linkedMapOf("seq" to n, "pad" to pad)
    }

/** agent_test.go `testMetric`. */
fun testMetric(n: Int): SecurityMetric =
    SecurityMetric(null, MetricTypes.REQUEST_COUNT, n.toDouble())

/** agent_test.go `waitUntil`: polls a condition with a deadline. */
fun waitUntil(
    timeout: Duration,
    msg: String,
    cond: () -> Boolean,
) {
  val deadline = System.nanoTime() + timeout.toNanos()
  while (System.nanoTime() < deadline) {
    if (cond()) {
      return
    }
    Thread.sleep(5)
  }
  error("condition not met within $timeout: $msg")
}

/** A quiet logger for tests that assert on log output instead of noise. */
fun quietLogger(): Logger =
    Logger.getLogger("guardagent-test-" + System.nanoTime()).apply {
      useParentHandlers = false
      java.util.logging.Level.WARNING.let { level = java.util.logging.Level.OFF }
    }

/** A collecting logger whose records tests assert on (agent_test.go log buffer). */
class CapturingLogger : Logger("guardagent-capture-" + System.nanoTime(), null) {
  val records = mutableListOf<String>()

  init {
    useParentHandlers = false
    level = java.util.logging.Level.ALL
    addHandler(
        object : java.util.logging.Handler() {
          override fun publish(record: java.util.logging.LogRecord) {
            synchronized(records) { records.add(record.message) }
          }

          override fun flush() {}

          override fun close() {}
        },
    )
  }

  fun output(): String = synchronized(records) { records.joinToString("\n") }

  fun count(substring: String): Int =
      synchronized(records) { records.count { it.contains(substring) } }
}

/** A per-test temp directory (the Go t.TempDir analog). */
fun tempDirFor(label: String): Path = Files.createTempDirectory("guard-agent-jvm-test-$label")

/** The panic-injection transport seam (agent_test.go panicRoundTripper). */
class AgentTestPanicDoer : HttpDoer {
  override fun execute(
      request: HttpRequest,
      body: ByteArray,
      ctx: AgentContext,
  ): HttpResponse<ByteArray> = throw IllegalStateException("transport panic")
}
