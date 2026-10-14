package com.guardcore.agent

import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Redis persistence runs off the request path and off the buffer mutex. Slow writes are gated on
 * latches (the Persistence command fault injector blocks inside the SET), never on sleeps. Needs
 * Redis on REDIS_HOST:6379, like PersistenceIntegrationTest; skips when unreachable.
 */
class PersistOffLockTest {
  private val closers = mutableListOf<AutoCloseable>()
  private val wait = Duration.ofSeconds(15)

  @AfterTest
  fun cleanup() {
    for (c in closers.reversed()) {
      try {
        c.close()
      } catch (ignored: Exception) {}
    }
    closers.clear()
  }

  private fun host(): String? {
    val h = System.getenv("REDIS_HOST") ?: "127.0.0.1"
    return try {
      val client = io.lettuce.core.RedisClient.create("redis://$h:6379")
      val conn = client.connect()
      val pong = conn.sync().ping()
      conn.close()
      client.shutdown()
      if (pong == "PONG") h else null
    } catch (e: Exception) {
      null
    }
  }

  private class Rig(
      val agent: GuardAgent,
      val mock: MockIngest,
      val prefix: String,
      val host: String,
      val entered: CountDownLatch,
      val gate: CountDownLatch,
  ) {
    fun keys(): List<String> {
      val client = io.lettuce.core.RedisClient.create("redis://$host:6379")
      val conn = client.connect()
      try {
        return conn.sync().keys("$prefix:*")
      } finally {
        conn.close()
        client.shutdown()
      }
    }
  }

  /** An agent whose first [blocked] SET calls park on `gate` until the test opens it. */
  private fun rig(blocked: Int = 1): Rig? {
    val h = host() ?: return null
    val mock = MockIngest()
    closers.add(mock)
    val prefix = "guardagent-offlock-" + System.nanoTime()
    val entered = CountDownLatch(blocked)
    val gate = CountDownLatch(1)
    val seen = AtomicInteger()
    val agent =
        newTestAgent(tempDirFor("offlock"), mock) { cfg ->
          cfg.retryAttempts = 0
          cfg.redis = RedisConfig("redis://$h:6379", prefix, Duration.ofMinutes(1))
        }
    agent.persist!!.commandFaultInjector = { name ->
      if (name == "set" && seen.incrementAndGet() <= blocked) {
        entered.countDown()
        gate.await(30, TimeUnit.SECONDS)
      }
      null
    }
    val rig = Rig(agent, mock, prefix, h, entered, gate)
    closers.add(
        AutoCloseable {
          gate.countDown()
          agent.stop()
          val client = io.lettuce.core.RedisClient.create("redis://$h:6379")
          val conn = client.connect()
          val ks = conn.sync().keys("$prefix:*")
          if (ks.isNotEmpty()) conn.sync().del(*ks.toTypedArray())
          conn.close()
          client.shutdown()
        },
    )
    return rig
  }

  private fun inThread(block: () -> Unit): CountDownLatch {
    val done = CountDownLatch(1)
    Thread {
      try {
        block()
      } finally {
        done.countDown()
      }
    }
        .apply { isDaemon = true }
        .start()
    return done
  }

  private fun awaitPersistDone(r: Rig, tasks: Long) {
    waitUntil(wait, "persist tasks complete") {
      r.agent.persistPool!!.completedTaskCount >= tasks
    }
  }

  @Test
  fun sendReturnsBeforeSlowWriteCompletes() {
    val r = rig() ?: return
    val sent = inThread { r.agent.sendEvent(testEvent(1)) }
    assertTrue(r.entered.await(15, TimeUnit.SECONDS), "write never started")
    assertTrue(sent.await(15, TimeUnit.SECONDS), "sendEvent must not wait for the Redis write")
    r.gate.countDown()
    awaitPersistDone(r, 1)
    waitUntil(wait, "key tracked") {
      synchronized(r.agent.mutex) { r.agent.events[0].key.isNotEmpty() }
    }
    assertEquals(1, r.keys().size)
  }

  @Test
  fun concurrentSendsAreNotSerializedBehindSlowWrite() {
    val r = rig() ?: return
    val first = inThread { r.agent.sendEvent(testEvent(1)) }
    assertTrue(r.entered.await(15, TimeUnit.SECONDS))
    val second = inThread { r.agent.sendEvent(testEvent(2)) }
    val third = inThread { r.agent.sendMetric(testMetric(3)) }
    assertTrue(first.await(15, TimeUnit.SECONDS))
    assertTrue(second.await(15, TimeUnit.SECONDS), "second send blocked behind the slow write")
    assertTrue(third.await(15, TimeUnit.SECONDS), "metric send blocked behind the slow write")
    assertTrue(
        synchronized(r.agent.mutex) { r.agent.events.size == 2 && r.agent.metrics.size == 1 },
    )
    r.gate.countDown()
    awaitPersistDone(r, 3)
  }

  @Test
  fun stopDrainsPendingPersists() {
    val r = rig() ?: return
    r.agent.sendEvent(testEvent(1))
    assertTrue(r.entered.await(15, TimeUnit.SECONDS))
    val stopped = inThread { r.agent.stop() }
    assertFalse(stopped.await(200, TimeUnit.MILLISECONDS), "stop returned with a persist in flight")
    r.gate.countDown()
    assertTrue(stopped.await(30, TimeUnit.SECONDS), "stop never finished")
    // The write landed before the final flush, which then confirmed (deleted) it.
    waitUntil(wait, "key confirmed after final flush") { r.keys().isEmpty() }
    assertEquals(1, r.mock.allCalls().count { it.events.isNotEmpty() })
  }

  @Test
  fun flushDuringPersistDeletesTheKey() {
    val r = rig() ?: return
    r.agent.sendEvent(testEvent(1))
    assertTrue(r.entered.await(15, TimeUnit.SECONDS))
    assertNull(r.agent.flush())
    r.gate.countDown()
    awaitPersistDone(r, 1)
    waitUntil(wait, "late key deleted, not orphaned") { r.keys().isEmpty() }
  }

  @Test
  fun requeueDuringPersistTracksTheKey() {
    val r = rig() ?: return
    r.agent.sendEvent(testEvent(1))
    assertTrue(r.entered.await(15, TimeUnit.SECONDS))
    r.mock.failNext(1)
    assertNotNull(r.agent.flush(), "flush should fail and requeue")
    assertEquals(1, synchronized(r.agent.mutex) { r.agent.events.size })
    r.gate.countDown()
    awaitPersistDone(r, 1)
    waitUntil(wait, "key tracked on the requeued item") {
      synchronized(r.agent.mutex) { r.agent.events[0].key.isNotEmpty() }
    }
    assertEquals(1, r.keys().size)
  }

  @Test
  fun nothingStartedWithoutPersistence() {
    val agent = newTestAgent(tempDirFor("nopersist"), null)
    closers.add(AutoCloseable { agent.stop() })
    assertNull(agent.persistPool)
    agent.sendEvent(testEvent(1))
    agent.sendMetric(testMetric(1))
    assertEquals(1, synchronized(agent.mutex) { agent.events.size })
    assertEquals("", synchronized(agent.mutex) { agent.events[0].key })
  }

  @Test
  fun startupEncryptionErrorIncludesCause() {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.projectEncryptionKey = "not-a-valid-key"
    val err = kotlin.test.assertFailsWith<EncryptionConfigError> { GuardAgent.create(cfg) }
    assertTrue(err.message!!.contains("refusing plaintext fallback"), err.message)
    assertTrue(err.message!!.contains("(cause: "), err.message)
    assertNotNull(err.cause)
    assertTrue(err.message!!.contains(err.cause!!.message ?: err.cause!!::class.java.simpleName))
  }
}
