package com.guardcore.agent

import io.lettuce.core.KeyScanCursor
import io.lettuce.core.RedisClient
import io.lettuce.core.RedisURI
import io.lettuce.core.ScanArgs
import io.lettuce.core.SetArgs
import io.lettuce.core.api.StatefulRedisConnection
import java.net.URI
import java.time.Duration
import java.util.logging.Logger

/**
 * Port of guard-agent-go `persistence.go`: Redis persistence, mirroring guard-agent (Python)
 * _buffer_redis.py: globally-unique "{prefix}:{namespace}:{short}" keys under the "agent_events"
 * and "agent_metrics" namespaces, written on enqueue with a TTL, deleted on confirmation, and
 * reloaded on start. Every Redis failure is fail-open: the agent logs, counts, and keeps operating
 * from memory.
 */
internal const val PERSIST_NAMESPACE_EVENTS: String = "agent_events"
internal const val PERSIST_NAMESPACE_METRICS: String = "agent_metrics"

/**
 * persistence.go `persistOpTimeout`: bounds one Redis round trip so a misbehaving Redis can never
 * stall the host application's request path for long.
 */
internal val PERSIST_OP_TIMEOUT: Duration = Duration.ofSeconds(2)

/**
 * After this many consecutive failed writes, persistence pauses for REDIS_FAILURE_COOLDOWN so an
 * unhealthy Redis cannot tax every enqueue.
 */
internal const val REDIS_MAX_CONSECUTIVE_FAILURES: Int = 3
internal val REDIS_FAILURE_COOLDOWN: Duration = Duration.ofSeconds(30)

/** persistence.go `persistScanCount`: the SCAN page size used during startup reload. */
internal const val PERSIST_SCAN_COUNT: Int = 200

/** persistence.go `persistedItem`: one reloaded record. */
internal class PersistedItem(
    val short: String,
    val value: String,
)

internal class Persistence(
    redisUrl: String,
    internal val prefix: String,
    private val ttl: Duration,
    private val logger: Logger,
) {
  private val client: RedisClient
  private val connection: StatefulRedisConnection<String, String> by lazy {
    client.connect()
  }

  init {
    val uri =
        try {
          RedisURI.create(URI.create(redisUrl))
        } catch (e: Exception) {
          throw IllegalArgumentException(e.message ?: "invalid redis url", e)
        }
    uri.setTimeout(PERSIST_OP_TIMEOUT)
    client = RedisClient.create(uri)
    client.setOptions(
        io.lettuce.core.ClientOptions.builder()
            .timeoutOptions(
                io.lettuce.core.TimeoutOptions.builder()
                    .fixedTimeout(PERSIST_OP_TIMEOUT)
                    .timeoutCommands(true)
                    .build(),
            )
            .build(),
    )
  }

  /**
   * persistence.go `shortKey`: the globally-unique short part of a persistence key:
   * "{kind}_{unix_nanos}_{8 hex chars}".
   */
  fun shortKey(kind: String): String = kind + "_" + System.nanoTime() + "_" + randomHex(4)

  fun fullKey(
      namespace: String,
      short: String,
  ): String = prefix + ":" + namespace + ":" + short

  companion object {
    /** persistence.go `shortOf`. */
    fun shortOf(fullKey: String): String {
      val i = fullKey.lastIndexOf(':')
      return if (i >= 0) fullKey.substring(i + 1) else fullKey
    }
  }

  /**
   * The go-redis hook analog: tests inject per-command faults by returning an exception for a
   * command name. Null in production.
   */
  @Volatile internal var commandFaultInjector: ((name: String) -> RuntimeException?)? = null

  /** Thrown by the injector to signal redis.Nil (a vanished record). */
  internal class RedisNilSignal(message: String) : RuntimeException(message)

  private inline fun <T> hooked(
      name: String,
      block: () -> T,
  ): T {
    commandFaultInjector?.let { inject -> inject(name)?.let { throw it } }
    return block()
  }

  private val stateLock = Any()
  private var consecutiveFailures: Int = 0
  private var cooldownUntil: java.time.Instant = java.time.Instant.EPOCH
  internal var failures: Long = 0
    private set

  /**
   * persistence.go `storeAvailable`: reports whether write attempts should proceed. After
   * REDIS_MAX_CONSECUTIVE_FAILURES consecutive failures writes pause for REDIS_FAILURE_COOLDOWN.
   */
  fun storeAvailable(): Boolean {
    synchronized(stateLock) {
      return !java.time.Instant.now().isBefore(cooldownUntil)
    }
  }

  /**
   * persistence.go `store`: writes value under key with the configured TTL. It returns true only
   * when the record is durable. Failures are fail-open: logged, counted, and subject to the write
   * cooldown.
   */
  fun store(
      key: String,
      value: String,
  ): Boolean {
    if (!storeAvailable()) {
      return false
    }
    var errMessage = "redis unavailable"
    val ok =
        try {
          val sync = connection.sync()
          hooked("set") { sync.set(key, value, SetArgs.Builder.ex(ttl.seconds)) != null }
        } catch (e: Exception) {
          errMessage = e.message ?: e::class.java.simpleName
          false
        }
    if (ok) {
      synchronized(stateLock) { consecutiveFailures = 0 }
      return true
    }
    synchronized(stateLock) {
      failures++
      consecutiveFailures++
      if (consecutiveFailures >= REDIS_MAX_CONSECUTIVE_FAILURES) {
        cooldownUntil = java.time.Instant.now().plus(REDIS_FAILURE_COOLDOWN)
        consecutiveFailures = 0
        logger.warning(
            "guardagent: redis persistence failing ($errMessage); pausing persist writes for $REDIS_FAILURE_COOLDOWN",
        )
      } else {
        logger.warning("guardagent: redis persist failed for $key: $errMessage")
      }
    }
    return false
  }

  /**
   * persistence.go `del`: deletes confirmed records. It is best effort: the TTL is the backstop, so
   * failures are logged but never surfaced.
   */
  fun del(keys: List<String>) {
    if (keys.isEmpty()) {
      return
    }
    try {
      val sync = connection.sync()
      hooked("del") { sync.del(*keys.toTypedArray()) }
    } catch (e: Exception) {
      logger.warning(
          "guardagent: redis confirm (delete) failed for ${keys.size} key(s): ${e.message}",
      )
    }
  }

  /**
   * persistence.go `loadKind`: scans a namespace and reads every live record, oldest short key
   * first. The short key embeds unix nanos, so lexicographic order is chronological for the
   * foreseeable future.
   */
  fun loadKind(namespace: String): List<PersistedItem> {
    val sync = connection.sync()
    val pattern = prefix + ":" + namespace + ":*"
    val shorts = mutableListOf<String>()
    var cursor = "0"
    while (true) {
      val page: KeyScanCursor<String> =
          hooked("scan") {
            sync.scan(
                io.lettuce.core.ScanCursor.of(cursor),
                ScanArgs.Builder.matches(pattern).limit(PERSIST_SCAN_COUNT.toLong()),
            )
          }
      shorts.addAll(page.keys)
      cursor = page.cursor
      if (cursor == "0") {
        break
      }
    }
    shorts.sort()
    val items = mutableListOf<PersistedItem>()
    for (full in shorts) {
      // redis.Nil (key gone between scan and read) skips; other read errors
      // surface to the caller, mirroring the Go error return.
      val value: String? =
          try {
            hooked("get") { sync.get(full) }
          } catch (e: RedisNilSignal) {
            null
          } ?: continue
      items.add(PersistedItem(shortOf(full), value ?: ""))
    }
    return items
  }

  fun close() {
    try {
      connection.close()
    } catch (e: Exception) {
      // Best-effort close; the process is shutting down.
    }
    client.shutdown()
  }
}
