package com.guardcore.agent

import java.time.Duration
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `coverage_integration_test.go` + `integration_test.go`: Redis-backed
 * durability branches, driven against the real Redis from CI with a command fault injector for
 * deterministic failure paths (the go-redis hook analog). Tests PING REDIS_HOST (default
 * 127.0.0.1:6379) and skip when it is unreachable; CI runs a redis service container.
 */
class PersistenceIntegrationTest {
  private val closers = mutableListOf<AutoCloseable>()

  @AfterTest
  fun cleanup() {
    for (c in closers.reversed()) {
      try {
        c.close()
      } catch (ignored: Exception) {}
    }
    closers.clear()
  }

  // ------------------------------------------------------------- helpers --

  /** integration_test.go `integrationRedisHost`: REDIS_HOST or the skip. */
  private fun redisHost(): String? {
    val host = System.getenv("REDIS_HOST") ?: "127.0.0.1"
    return try {
      val conn = io.lettuce.core.RedisClient.create("redis://$host:6379").connect()
      val pong = conn.sync().ping()
      conn.close()
      if (pong == "PONG") host else null
    } catch (e: Exception) {
      null
    }
  }

  /** coverage_integration_test.go `uniqueSuffix`: per-run key namespace. */
  private fun uniqueSuffix(): String = "r" + System.nanoTime()

  /** integration_test.go `scanAll`: a full SCAN iteration. */
  private fun scanAll(
      client: io.lettuce.core.api.StatefulRedisConnection<String, String>,
      pattern: String,
  ): List<String> {
    val out = mutableListOf<String>()
    var cursor = "0"
    while (true) {
      val page =
          try {
            client
                .sync()
                .scan(
                    io.lettuce.core.ScanCursor.of(cursor),
                    io.lettuce.core.ScanArgs.Builder.matches(pattern).limit(100),
                )
          } catch (e: Exception) {
            return out
          }
      out.addAll(page.keys)
      cursor = page.cursor
      if (cursor == "0") return out
    }
  }

  private fun newClient(host: String): io.lettuce.core.api.StatefulRedisConnection<String, String> {
    val client = io.lettuce.core.RedisClient.create("redis://$host:6379")
    val conn = client.connect()
    closers.add(
        AutoCloseable {
          conn.close()
          client.shutdown()
        },
    )
    return conn
  }

  private fun deleteTestKeys(
      client: io.lettuce.core.api.StatefulRedisConnection<String, String>,
      pattern: String,
  ) {
    val keys = scanAll(client, pattern)
    if (keys.isNotEmpty()) {
      client.sync().del(*keys.toTypedArray())
    }
  }

  private fun hookedPersistence(
      host: String,
      prefix: String,
      mutate: ((Persistence) -> Unit)? = null,
  ): Persistence {
    val p = Persistence("redis://$host:6379", prefix, Duration.ofMinutes(1), quietLogger())
    mutate?.invoke(p)
    closers.add(
        AutoCloseable {
          try {
            val conn = io.lettuce.core.RedisClient.create("redis://$host:6379").connect()
            val keys = scanAll(conn, prefix + ":*")
            if (keys.isNotEmpty()) {
              conn.sync().del(*keys.toTypedArray())
            }
            conn.close()
          } catch (ignored: Exception) {}
          p.close()
        },
    )
    return p
  }

  private fun newIntegrationAgent(
      host: String,
      endpoint: String,
      mutate: ((AgentConfig) -> Unit)? = null,
  ): GuardAgent {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.endpoint = endpoint
    cfg.flushInterval = Duration.ofHours(1)
    cfg.statusInterval = Duration.ofHours(1)
    cfg.retryAttempts = 0
    cfg.installIdPath = tempDirFor("integ-agent").resolve("install-id").toString()
    cfg.redis = RedisConfig("redis://$host:6379", INTEGRATION_REDIS_PREFIX, Duration.ofMinutes(1))
    mutate?.invoke(cfg)
    val agent = GuardAgent.create(cfg)
    closers.add(AutoCloseable { agent.stop() })
    return agent
  }

  // -------------------------------------------------- persistence units --

  @Test
  fun persistenceStoreCooldownAndReset() {
    val host = redisHost() ?: return
    val dead =
        hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":store:" + uniqueSuffix()) { p ->
          p.commandFaultInjector = { name ->
            if (name == "set") RuntimeException("redis exploded") else null
          }
        }
    // The dead-write path is logged per failure...
    assertFalse(dead.store("k1", "v"), "writes against a failing redis must report not-durable")
    assertFalse(dead.store("k2", "v"))
    // ...and pause after three consecutive failures.
    assertFalse(dead.store("k3", "v"))
    assertFalse(dead.storeAvailable(), "three consecutive failures must arm the write cooldown")
    assertFalse(dead.store("k4", "v"), "writes during the cooldown must not even be attempted")

    // A success between failures resets the consecutive counter.
    var fails = 0
    val spy =
        hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":reset:" + uniqueSuffix()) { p ->
          p.commandFaultInjector = { name ->
            if (name == "set") {
              fails++
              if (fails == 1) RuntimeException("redis exploded once") else null
            } else {
              null
            }
          }
        }
    assertFalse(spy.store("k1", "v"), "the first write must fail")
    assertTrue(spy.store("k2", "v"), "the retry write must succeed once redis recovers")
    assertTrue(spy.store("k3", "v"), "writes must stay available after a recovery")
  }

  @Test
  fun persistenceDelEmptyAndFailure() {
    val host = redisHost() ?: return
    val p = hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":del:" + uniqueSuffix())
    p.del(emptyList()) // empty deletes are no-ops

    val failing =
        hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":del:" + uniqueSuffix()) { p ->
          p.commandFaultInjector = { name ->
            if (name == "del") RuntimeException("del exploded") else null
          }
        }
    failing.del(listOf("k1", "k2")) // logged, never surfaced
  }

  @Test
  fun loadKindHandlesScanAndReadErrors() {
    val host = redisHost() ?: return
    val scanFailing =
        hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":scan:" + uniqueSuffix()) { p ->
          p.commandFaultInjector = { name ->
            if (name == "scan") RuntimeException("scan exploded") else null
          }
        }
    assertFailsWithMessage("scan exploded") { scanFailing.loadKind(PERSIST_NAMESPACE_EVENTS) }

    // Seed one live record; the GET hook reports it vanished (redis.Nil)
    // or broken, per scenario.
    fun seed(hookErr: RuntimeException?): Persistence {
      val p =
          hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":get:" + uniqueSuffix()) { pp ->
            pp.commandFaultInjector = { name ->
              if (name == "get" && hookErr != null) hookErr else null
            }
          }
      assertTrue(
          p.store(p.fullKey(PERSIST_NAMESPACE_EVENTS, "event_seed"), "{\"event_type\":\"seed\"}"),
          "seed write must be durable",
      )
      return p
    }

    val vanished = seed(Persistence.RedisNilSignal("redis: nil"))
    val items = vanished.loadKind(PERSIST_NAMESPACE_EVENTS)
    assertEquals(0, items.size, "a vanished record must not be reloaded")

    val broken = seed(RuntimeException("get exploded"))
    var surfaced: Throwable? = null
    try {
      broken.loadKind(PERSIST_NAMESPACE_EVENTS)
    } catch (err: Exception) {
      surfaced = err
    }
    assertTrue(surfaced != null, "a failing read must surface")
  }

  private inline fun assertFailsWithMessage(
      needle: String,
      block: () -> Any?,
  ) {
    var err: Throwable? = null
    try {
      block()
    } catch (t: Throwable) {
      err = t
    }
    assertTrue(
        err != null && err!!.message!!.contains(needle),
        "expected failure containing \"$needle\", got $err",
    )
  }

  @Test
  fun loadKindPagesThroughLargeNamespaces() {
    val host = redisHost() ?: return
    val p = hookedPersistence(host, INTEGRATION_REDIS_PREFIX + ":pages:" + uniqueSuffix())
    for (i in 0 until 250) {
      val key = p.fullKey(PERSIST_NAMESPACE_EVENTS, "event_%04d".format(i))
      assertTrue(p.store(key, "{\"event_type\":\"e$i\"}"), "seed write $i must be durable")
    }
    val items = p.loadKind(PERSIST_NAMESPACE_EVENTS)
    assertEquals(250, items.size, "every record must reload across scan pages")
    assertTrue(items[0].short < items.last().short, "records must reload oldest first")
  }

  // -------------------------------------------------------- agent-level --

  @Test
  fun overflowDropConfirmsEvictedPersistedMetric() {
    val host = redisHost() ?: return
    val prefix = INTEGRATION_REDIS_PREFIX + ":mdrop:" + uniqueSuffix()
    val client = newClient(host)
    val mock = MockIngest()
    val agent =
        newIntegrationAgent(host, mock.url) { c ->
          c.bufferSize = 1
          c.highWatermarkRatio = 1.0
          c.redis = RedisConfig("redis://$host:6379", prefix, Duration.ofMinutes(1))
        }
    try {
      agent.sendMetric(testMetric(1))
      // The buffer holds one metric; the second evicts the first, whose
      // persisted record must be confirmed (deleted).
      agent.sendMetric(testMetric(2))
      waitUntil(Duration.ofSeconds(5), "the evicted record must be deleted") {
        scanAll(client, prefix + ":agent_metrics:*").size == 1
      }
    } finally {
      agent.stop()
      mock.close()
      deleteTestKeys(client, prefix + ":*")
    }
  }

  @Test
  fun reloadFromRedisRestoresDropsAndEvicts() {
    val host = redisHost() ?: return
    val prefix = INTEGRATION_REDIS_PREFIX + ":reload:" + uniqueSuffix()
    val client = newClient(host)
    fun validEvent(n: Int): String = goJson(testEvent(n)).toString(Charsets.UTF_8)
    val corrupt = "{not json"

    // Controlled short keys keep the lexicographic (chronological) reload
    // order deterministic.
    val eventShorts = listOf("event_0001", "event_0002", "event_0003", "event_0004")
    // Four events over a two-slot buffer: the two oldest must be evicted
    // (and deleted) so they cannot resurrect, leaving the newest two.
    val values = listOf(validEvent(1), validEvent(2), validEvent(3), validEvent(4))
    for ((i, short) in eventShorts.withIndex()) {
      client.sync().setex(prefix + ":agent_events:" + short, 60, values[i])
    }
    val corruptShort = "event_ffff"
    client.sync().setex(prefix + ":agent_events:" + corruptShort, 60, corrupt)
    val metricShorts = listOf("metric_0001", "metric_0002", "metric_0003")
    for ((i, short) in metricShorts.withIndex()) {
      client
          .sync()
          .setex(
              prefix + ":agent_metrics:" + short,
              60,
              goJson(testMetric(i)).toString(Charsets.UTF_8),
          )
    }
    val corruptMetricShort = "metric_ffff"
    client.sync().setex(prefix + ":agent_metrics:" + corruptMetricShort, 60, corrupt)

    val tmp = tempDirFor("integ-reload")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.bufferSize = 2
          c.redis = RedisConfig("redis://$host:6379", prefix, Duration.ofMinutes(1))
        }
    try {
      agent.start()
      val stats = agent.stats()
      assertEquals(2, stats.eventsPending, "reload must cap at the buffer size: $stats")
      assertEquals(2, stats.metricsPending)
      // Every reloaded record counts as buffered, including the ones the
      // capacity guard evicts afterwards.
      assertEquals(4L, stats.eventsBuffered, "reload must count buffered items: $stats")
      assertEquals(3L, stats.metricsBuffered)
      // The corrupt records must be deleted so a later restart cannot
      // resurrect them, along with the evicted oldest records.
      for (short in
          eventShorts.take(2) + corruptShort + metricShorts.take(1) + corruptMetricShort) {
        val namespace =
            if (short.contains("metric")) PERSIST_NAMESPACE_METRICS else PERSIST_NAMESPACE_EVENTS
        val full = prefix + ":" + namespace + ":" + short
        assertEquals(
            0L,
            client.sync().exists(full),
            "record $full must be deleted after eviction or corruption",
        )
      }
      // The surviving records must be the newest ones.
      val first: String
      val second: String
      synchronized(agent.mutex) {
        first = agent.events[0].ev.eventType
        second = agent.events[1].ev.eventType
      }
      assertEquals("event_3", first, "reload must apply oldest first")
      assertEquals("event_4", second)
    } finally {
      agent.stop()
      deleteTestKeys(client, prefix + ":agent_*")
    }
  }

  @Test
  fun reloadSurvivesRedisOutage() {
    val host = redisHost() ?: return
    val logger = CapturingLogger()
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.endpoint = "http://127.0.0.1:1"
    cfg.installIdPath = tempDirFor("integ-outage").resolve("install-id").toString()
    cfg.redis =
        RedisConfig(
            "redis://$host:6379",
            INTEGRATION_REDIS_PREFIX + ":outage:" + uniqueSuffix(),
            Duration.ofMinutes(1),
        )
    val agent = GuardAgent.create(cfg, AgentOptions().withLogger(logger))
    closers.add(AutoCloseable { agent.stop() })
    // Break the scan so the startup reload fails: the agent must start
    // memory-only and count the failure.
    agent.persist!!.commandFaultInjector = { name ->
      if (name == "scan") RuntimeException("scan exploded") else null
    }
    agent.start()
    assertTrue(
        logger.output().contains("starting memory-only"),
        "a failing reload must degrade to memory-only",
    )
    assertTrue(
        agent.stats().redisPersistFailures > 0,
        "a failing reload must count a persistence failure",
    )
  }

  @Test
  fun agentPersistEnqueueConfirmLifecycle() {
    val host = redisHost() ?: return
    val prefix = INTEGRATION_REDIS_PREFIX + ":lifecycle:" + uniqueSuffix()
    val client = newClient(host)
    val mock = MockIngest()
    val agent =
        newIntegrationAgent(host, mock.url) { c ->
          c.redis = RedisConfig("redis://$host:6379", prefix, Duration.ofMinutes(1))
        }
    try {
      agent.sendEvent(testEvent(1))
      agent.sendMetric(testMetric(1))
      waitUntil(Duration.ofSeconds(5), "enqueue must persist records") {
        scanAll(client, prefix + ":agent_*").size == 2
      }
      assertEquals(null, agent.flush(), "flush")
      waitUntil(Duration.ofSeconds(5), "confirmation must delete the records") {
        scanAll(client, prefix + ":agent_*").isEmpty()
      }
    } finally {
      agent.stop()
      mock.close()
      deleteTestKeys(client, prefix + ":*")
    }
  }

  @Test
  fun confirmKeysOverflowsToDirectDeleteAndSurvivesStop() {
    val host = redisHost() ?: return
    val prefix = INTEGRATION_REDIS_PREFIX + ":confirm:" + uniqueSuffix()
    val client = newClient(host)
    val tmp = tempDirFor("integ-confirm")
    val agent =
        newTestAgent(tmp, null) { c ->
          c.redis = RedisConfig("redis://$host:6379", prefix, Duration.ofMinutes(1))
        }
    try {
      // Saturate the confirm queue: the keys must fall through to a
      // direct delete instead of being lost.
      for (i in 0 until 64) {
        agent.confirmQueue.offer(listOf(prefix + ":agent_events:filler_" + i))
      }
      agent.confirmKeys(listOf(prefix + ":agent_events:spill"))
      waitUntil(Duration.ofSeconds(5), "the spilled keys must delete directly") {
        client.sync().exists(prefix + ":agent_events:spill") == 0L
      }
      // Drain the queue so stop's worker exits cleanly.
      while (agent.confirmQueue.isNotEmpty()) {
        agent.confirmQueue.poll()
      }
    } finally {
      agent.stop()
      // After stop the confirm worker is closed: confirmKeys must fall
      // through to the direct delete and never throw.
      agent.confirmKeys(listOf(prefix + ":agent_events:after-stop"))
      deleteTestKeys(client, prefix + ":*")
    }
  }

  // --------------------------------------------- integration_test.go port --

  @Test
  fun integrationPersistsOnEnqueueWithTTL() {
    val host = redisHost() ?: return
    val client = newClient(host)
    val mock = MockIngest()
    val agent = newIntegrationAgent(host, mock.url)
    try {
      for (i in 1..2) agent.sendEvent(testEvent(i))
      agent.awaitPersists()
      val keys = scanAll(client, INTEGRATION_REDIS_PREFIX + ":*")
      assertEquals(2, keys.size, "persisted keys")
      for (key in keys) {
        assertTrue(
            key.startsWith(INTEGRATION_REDIS_PREFIX + ":" + PERSIST_NAMESPACE_EVENTS + ":"),
            "unexpected key shape $key",
        )
        val ttl = client.sync().ttl(key)
        assertTrue(
            ttl in 1..DEFAULT_PERSIST_TTL.seconds,
            "ttl got $ttl want within (0, ${DEFAULT_PERSIST_TTL.seconds}]",
        )
      }
      assertEquals(
          0L,
          agent.stats().redisPersistFailures,
          "healthy redis must not report persist failures",
      )
    } finally {
      agent.stop()
      mock.close()
      deleteTestKeys(client, INTEGRATION_REDIS_PREFIX + ":*")
    }
  }

  @Test
  fun integrationConfirmDeletesRecords() {
    val host = redisHost() ?: return
    val client = newClient(host)
    val mock = MockIngest()
    val agent = newIntegrationAgent(host, mock.url)
    try {
      agent.sendMetric(testMetric(1))
      agent.awaitPersists()
      assertEquals(
          1,
          scanAll(client, INTEGRATION_REDIS_PREFIX + ":*").size,
          "expected one persisted metric record",
      )
      assertEquals(null, agent.flush(), "flush")
      assertEquals(
          1,
          mock.callsTo(METRICS_PATH).size,
          "metric batch must reach the mock ingestion API",
      )
      waitUntil(Duration.ofSeconds(2), "confirmed records must be deleted") {
        scanAll(client, INTEGRATION_REDIS_PREFIX + ":*").isEmpty()
      }
    } finally {
      agent.stop()
      mock.close()
      deleteTestKeys(client, INTEGRATION_REDIS_PREFIX + ":*")
    }
  }

  @Test
  fun integrationReloadAfterRestart() {
    val host = redisHost() ?: return
    val client = newClient(host)
    // First run: the ingestion endpoint is down, so the batch fails, is
    // requeued, and stays persisted.
    val first = newIntegrationAgent(host, "http://127.0.0.1:1")
    run {
      for (i in 1..2) first.sendEvent(testEvent(i))
      first.awaitPersists()
      assertTrue(first.flush() != null, "flush against a down endpoint must fail")
      assertTrue(
          first.stop() != null,
          "stop with a down endpoint must report the final flush error",
      )
    }
    assertEquals(
        2,
        scanAll(client, INTEGRATION_REDIS_PREFIX + ":*").size,
        "records after failed run",
    )

    // Second run: a fresh agent with the same Redis prefix reloads the
    // records on start and delivers them in order.
    val mock = MockIngest()
    val second = newIntegrationAgent(host, mock.url)
    try {
      second.start()
      assertEquals(2, second.stats().eventsPending, "reloaded pending events")
      assertEquals(null, second.flush(), "flush")
      val calls = mock.callsTo(EVENTS_PATH)
      assertEquals(1, calls.size)
      assertEquals(2, calls[0].events.size)
      assertEquals("event_1", calls[0].events[0].eventType, "reload order")
      assertEquals("event_2", calls[0].events[1].eventType)
      waitUntil(Duration.ofSeconds(2), "reloaded records must be confirmed") {
        scanAll(client, INTEGRATION_REDIS_PREFIX + ":*").isEmpty()
      }
    } finally {
      second.stop()
      mock.close()
      deleteTestKeys(client, INTEGRATION_REDIS_PREFIX + ":*")
    }
  }

  @Test
  fun integrationDropEvictsPersistedRecord() {
    val host = redisHost() ?: return
    val client = newClient(host)
    val mock = MockIngest()
    val agent = newIntegrationAgent(host, mock.url) { c -> c.bufferSize = 1 }
    try {
      agent.sendEvent(testEvent(1))
      agent.sendEvent(testEvent(2))
      assertEquals(1L, agent.stats().eventsDropped, "dropped")
      waitUntil(
          Duration.ofSeconds(2),
          "the evicted record must be deleted so it cannot resurrect",
      ) {
        scanAll(client, INTEGRATION_REDIS_PREFIX + ":*").size == 1
      }
      val keys = scanAll(client, INTEGRATION_REDIS_PREFIX + ":*")
      val value = client.sync().get(keys[0])
      assertTrue(
          value.contains("event_2") && !value.contains("event_1"),
          "surviving record must be event_2, got $value",
      )
    } finally {
      agent.stop()
      mock.close()
      deleteTestKeys(client, INTEGRATION_REDIS_PREFIX + ":*")
    }
  }

  @Test
  fun integrationRedisFailOpen() {
    redisHost() ?: return // keep the skip behavior consistent
    val mock = MockIngest()
    val agent =
        newIntegrationAgent("127.0.0.1", mock.url) { c ->
          c.redis =
              RedisConfig("redis://127.0.0.1:1", INTEGRATION_REDIS_PREFIX, Duration.ofMinutes(1))
        }
    try {
      agent.start()
      agent.sendEvent(testEvent(1))
      assertEquals(null, agent.flush(), "flush with redis down")
      assertEquals(
          1,
          mock.callsTo(EVENTS_PATH).size,
          "telemetry must still be delivered without redis",
      )
      agent.awaitPersists()
      val stats = agent.stats()
      assertTrue(stats.redisPersistFailures > 0, "redis failures must be counted: $stats")
      assertTrue(stats.durabilityDegraded, "durability must be reported degraded")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  companion object {
    private const val INTEGRATION_REDIS_PREFIX: String = "guard_agent_jvm_test"
  }
}
