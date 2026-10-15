package com.guardcore.agent

import java.time.Duration
import java.time.Instant
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.logging.Logger

/**
 * Port of guard-agent-go `agent.go`. GuardAgent buffers security telemetry and ships it to the
 * Guard Core App ingestion API with at-least-once semantics. Construct with [GuardAgent.create];
 * call [start] to begin the background flush and status loops (buffering works before start); call
 * [stop] to cancel the loops and attempt one final forced flush.
 *
 * Failure isolation policy: no exported method ever throws an unexpected exception; telemetry
 * failures are logged and counted and, where idiomatic, thrown as errors that callers may freely
 * ignore. The only error sendEvent and sendMetric can throw under the default [OverflowPolicy.DROP]
 * policy is [ErrorKind.CLOSED] after stop.
 */
public class GuardAgent
internal constructor(
    internal val cfg: AgentConfig,
    internal val logger: Logger,
    internal val installId: String,
) {
  internal var persist: Persistence? = null
  internal lateinit var tr: Transport

  internal val mutex = Any()
  internal val events = ArrayList<BufferedEvent>()
  internal val metrics = ArrayList<BufferedMetric>()

  // Lifetime counters, guarded by mutex exactly like the Go fields.
  internal var eventsBuffered: Long = 0
  internal var metricsBuffered: Long = 0
  internal var eventsFlushed: Long = 0
  internal var metricsFlushed: Long = 0
  internal var eventsSent: Long = 0
  internal var metricsSent: Long = 0
  internal var eventsFailed: Long = 0
  internal var metricsFailed: Long = 0
  internal var eventsDropped: Long = 0
  internal var metricsDropped: Long = 0
  internal var redisPersistFailures: Long = 0
  internal var statusSent: Long = 0
  internal var statusFailed: Long = 0
  internal var statusStreak: Int = 0
  internal var eventStreak: Int = 0
  internal var metricStreak: Int = 0
  internal var eventGate: Instant = Instant.EPOCH
  internal var metricGate: Instant = Instant.EPOCH
  internal var lastFlush: Instant = Instant.EPOCH
  internal var lastErrors: MutableList<String> = mutableListOf()
  internal var rulesFetched: Long = 0
  internal var cachedRules: DynamicRules? = null
  internal var rulesLastUpdate: Instant = Instant.EPOCH

  @Volatile internal var started: Boolean = false
  @Volatile internal var closed: Boolean = false
  internal var startedAt: Instant = Instant.EPOCH

  /** The detached loop context: created at start, canceled at stop. */
  @Volatile private var loopContext: AgentContext = AgentContext.NONE

  /** flushWake wakes one persistent flusher thread when the high-watermark is reached. */
  internal val flushWake = ArrayBlockingQueue<Any>(1)

  /** flushSignal wakes block-policy waiters when a drain frees space. */
  private val flushSignal = ArrayBlockingQueue<Any>(1)

  /** confirmQueue serializes Redis confirmations on one worker thread. */
  internal val confirmQueue = LinkedBlockingQueue<List<String>>(64)

  /**
   * Redis persists run here, never on the caller's thread and never under [mutex]; [stop] waits for
   * them. Null when persistence is not configured, so nothing is started then.
   */
  internal var persistPool: java.util.concurrent.ThreadPoolExecutor? = null

  @Volatile private var confirmClosed: Boolean = false
  private val workerDone = CountDownLatch(1)
  private val loopThreads = mutableListOf<Thread>()

  private val wakeToken = Object()

  // -------------------------------------------------------------- models --

  /** agent.go `bufferedEvent`: one queued event plus its persistence key. */
  internal class BufferedEvent(
      val ev: SecurityEvent,
      @Volatile var key: String,
      val reserved: String = "",
  )

  internal class BufferedMetric(
      val m: SecurityMetric,
      @Volatile var key: String,
      val reserved: String = "",
  )

  /** agent.go `Status`: a point-in-time snapshot of the agent's health and counters. */
  public class AgentStatus {
    /** [AgentStatusValues.HEALTHY], [AgentStatusValues.DEGRADED], or [AgentStatusValues.FAILED]. */
    public var state: String = ""

    /** The time since start; zero before start. */
    public var uptime: Duration = Duration.ZERO

    /** Lifetime counters. Permanently rejected batches count as sent. */
    public var eventsSent: Long = 0
    public var eventsFailed: Long = 0

    /** The combined events+metrics occupancy. */
    public var bufferSize: Int = 0

    /** The most recent drain time; null before the first flush. */
    public var lastFlush: Instant? = null

    /** The most recent failure messages, oldest first. */
    public var errors: List<String> = emptyList()

    /** "closed", "open", or "half_open". */
    public var circuitState: String = ""
  }

  /** agent.go `Stats`: lifetime counters. */
  public class AgentStatsSnapshot {
    public var eventsBuffered: Long = 0
    public var metricsBuffered: Long = 0
    public var eventsFlushed: Long = 0
    public var metricsFlushed: Long = 0
    public var eventsSent: Long = 0
    public var metricsSent: Long = 0
    public var eventsFailed: Long = 0
    public var metricsFailed: Long = 0
    public var eventsDropped: Long = 0
    public var metricsDropped: Long = 0
    public var eventsPending: Int = 0
    public var metricsPending: Int = 0
    public var redisPersistFailures: Long = 0

    /** True when Redis persistence is configured but at least one persist failed. */
    public var durabilityDegraded: Boolean = false
    public var statusReportsSent: Long = 0
    public var statusReportsFailed: Long = 0
    public var rulesFetched: Long = 0
    public var requestsSent: Long = 0
    public var requestsFailed: Long = 0
    public var circuitState: String = ""
  }

  // --------------------------------------------------------- construction --

  public companion object {
    // Agent behavioral constants, mirroring guard-agent (Python).
    internal val BLOCK_POLL_INTERVAL: Duration = Duration.ofMillis(500)
    internal const val DROP_LOG_INTERVAL: Long = 100
    internal const val DEGRADED_BUFFER_RATIO: Double = 0.9
    internal const val HEALTH_BUFFER_RATIO: Double = 0.95
    internal const val DEGRADED_FAILURE_RATE: Double = 0.1
    internal const val HEALTH_FAILURE_RATE_MAX: Double = 0.5
    internal const val MAX_TRACKED_ERRORS: Int = 10
    internal const val PERSIST_THREADS: Int = 4
    internal const val PERSIST_QUEUE: Int = 1024
    internal const val PERSIST_DRAIN_MS: Long = 10_000
    internal const val KIND_EVENT: String = "event"
    internal const val KIND_METRIC: String = "metric"
    internal const val ENGINE_CLASS_NAME: String = "com.guardcore.engine.GuardCoreEngine"

    /**
     * agent.go `New`: validates cfg (filling defaults), resolves the install id, and returns an
     * agent. It performs no network I/O and never throws unexpected exceptions. Options:
     * [AgentOptions.withLogger] and [AgentOptions.withHttpClient].
     */
    public fun create(
        config: AgentConfig,
        options: AgentOptions = AgentOptions(),
    ): GuardAgent {
      val logger = options.logger ?: Logger.getLogger("guardagent")
      val normalized = normalize(config)
      normalized.error?.let { throw it }
      val cfg = normalized.cfg
      if (cfg.guardCoreVersion.isEmpty()) {
        cfg.guardCoreVersion = detectGuardCoreVersion(ENGINE_CLASS_NAME)
      }
      for (w in normalized.warnings) {
        logger.warning("guardagent: $w")
      }
      val installId = resolveInstallID(cfg.installId, cfg.installIdPath, logger)

      // Fail-closed encryption init (mirrors
      // _transport_lifecycle._init_encryption): when a key is configured, an
      // invalid key or a failed round-trip verification aborts construction;
      // plaintext fallback is forbidden.
      val encryptor =
          try {
            createEncryptor(cfg.projectEncryptionKey)
          } catch (encErr: Exception) {
            throw EncryptionConfigError(
                "Encryption round-trip failed at startup; refusing plaintext fallback " +
                    "(cause: ${encErr.message ?: encErr::class.java.simpleName})",
                encErr,
            )
          }
      if (encryptor != null && !encryptor.verifyKey()) {
        throw EncryptionConfigError(
            "Encryption round-trip failed at startup; refusing plaintext fallback",
        )
      }

      val agent = GuardAgent(cfg, logger, installId)
      agent.tr = Transport(cfg, installId, options.httpClient, logger)
      agent.tr.encryptor = encryptor
      cfg.redis?.let { redisCfg ->
        val persist =
            try {
              Persistence(redisCfg.url, redisCfg.prefix, redisCfg.ttl, logger)
            } catch (err: Exception) {
              throw AgentConfigException(
                  listOf(
                      "redis configuration invalid: ${err.message ?: err::class.java.simpleName}",
                  ),
              )
            }
        agent.persist = persist
        agent.persistPool =
            java.util.concurrent.ThreadPoolExecutor(
                PERSIST_THREADS,
                PERSIST_THREADS,
                0L,
                TimeUnit.MILLISECONDS,
                LinkedBlockingQueue(PERSIST_QUEUE),
            ) { r ->
              Thread(r, "guard-agent-persist").apply { isDaemon = true }
            }
        val worker = Thread({ agent.confirmWorker() }, "guard-agent-confirm")
        worker.isDaemon = true
        worker.start()
      }
      return agent
    }
  }

  // ------------------------------------------------------------- lifecycle --

  /**
   * agent.go `Start`: begins the periodic flush and status loops and reloads any persisted
   * telemetry from Redis. The ctx bounds startup work only: it is intentionally detached for the
   * background loops, which run until stop. Start is idempotent.
   */
  public fun start(ctx: AgentContext = AgentContext.NONE): Unit =
      isolated("Start") {
        synchronized(mutex) {
          if (closed) {
            throw GuardAgentException(Err.CLOSED, ErrorKind.CLOSED)
          }
          if (started) {
            return@isolated
          }
          loopContext = AgentContext.withCancel()
          started = true
          startedAt = Instant.now()
          if (persist != null) {
            reloadFromRedisLocked()
          }
          val flushers = maxOf(1, cfg.maxConcurrentFlushes)
          spawnLoop("guard-agent-autoflush") { autoFlushLoop() }
          repeat(flushers) { i -> spawnLoop("guard-agent-wakeflush-$i") { wakeFlushLoop() } }
          spawnLoop("guard-agent-status") { statusLoop() }
          spawnLoop("guard-agent-rules") { rulesLoop() }
        }
      }

  /**
   * agent.go `Stop`: cancels the background loops, attempts one final forced flush of both kinds
   * (bypassing the per-kind backoff gates), and releases resources. It is idempotent and returns
   * the final flush error, if any.
   */
  public fun stop(ctx: AgentContext = AgentContext.NONE): Throwable? =
      isolated("Stop") {
        synchronized(mutex) {
          if (closed) {
            return@isolated null
          }
          closed = true
        }
        loopContext.cancel()
        val threads = synchronized(mutex) { loopThreads.toList() }
        for (t in threads) {
          t.join(10_000)
        }
        persistPool?.let {
          it.shutdown()
          it.awaitTermination(PERSIST_DRAIN_MS, TimeUnit.MILLISECONDS)
        }
        val errE = flushEvents(ctx, force = true)
        val errM = flushMetrics(ctx, force = true)
        val err = joinErrors(errE, errM)
        if (persist != null) {
          confirmClosed = true
          workerDone.await()
          persist!!.close()
        }
        tr.closeIdleConnections()
        err
      }

  // --------------------------------------------------------------- sends --

  /**
   * agent.go `SendEvent`: buffers one security event. It never throws unexpected exceptions and,
   * under the default OverflowDrop policy, the only errors it can throw are [ErrorKind.CLOSED]
   * (after stop) and [ErrorKind.INVALID_EVENT] (validation). With OverflowBlock it waits for space
   * and throws the context error when the context ends first. With OverflowRaise it throws
   * [BufferFullError] when full.
   */
  public fun sendEvent(
      ctx: AgentContext,
      ev: SecurityEvent,
  ): Unit =
      isolated("SendEvent") {
        guardClosed()
        if (!cfg.enableEvents) {
          return@isolated
        }
        if (ev.eventType.isEmpty()) {
          throw GuardAgentException(
              "${Err.INVALID_EVENT}: event_type is required",
              ErrorKind.INVALID_EVENT,
          )
        }
        if (ev.timestamp == null) {
          ev.timestamp = Instant.now()
        }
        if (ev.idempotencyKey.isNullOrEmpty()) {
          ev.idempotencyKey = newUUID4()
        }
        val redacted = redactEventMetadata(ev, cfg.sensitiveHeaders)
        enqueueEvent(ctx, redacted)
      }

  /** Convenience overload with [AgentContext.NONE]. */
  public fun sendEvent(ev: SecurityEvent): Unit = sendEvent(AgentContext.NONE, ev)

  /**
   * agent.go `SendMetric`: buffers one numeric sample. MetricType must be one of the [MetricTypes]
   * constants. Failure isolation matches [sendEvent].
   */
  public fun sendMetric(
      ctx: AgentContext,
      m: SecurityMetric,
  ): Unit =
      isolated("SendMetric") {
        guardClosed()
        if (!cfg.enableMetrics) {
          return@isolated
        }
        if (!MetricTypes.isValid(m.metricType)) {
          throw GuardAgentException(
              "${Err.INVALID_EVENT}: metric_type \"${m.metricType}\" is not one of the accepted values",
              ErrorKind.INVALID_EVENT,
          )
        }
        if (m.timestamp == null) {
          m.timestamp = Instant.now()
        }
        val redacted = redactMetricTags(m, cfg.sensitiveHeaders)
        enqueueMetric(ctx, redacted)
      }

  /** Convenience overload with [AgentContext.NONE]. */
  public fun sendMetric(m: SecurityMetric): Unit = sendMetric(AgentContext.NONE, m)

  /**
   * agent.go `Flush`: drains and sends both kinds now, respecting the per-kind backoff gates. It
   * returns the transport error of any failed kind; callers may ignore it. Nothing acknowledged is
   * lost: on failure the batch is requeued in its original order.
   */
  public fun flush(ctx: AgentContext = AgentContext.NONE): Throwable? =
      isolated("Flush") {
        guardClosed()
        val errE = flushEvents(ctx, force = false)
        val errM = flushMetrics(ctx, force = false)
        joinErrors(errE, errM)
      }

  // ---------------------------------------------------------- observation --

  /**
   * agent.go `Status`: the current health snapshot. State is "failed" after stop, "degraded" while
   * the circuit breaker is open, the buffer is at or above 90% occupancy, or the lifetime failure
   * rate exceeds 10%; otherwise "healthy".
   */
  public fun status(): AgentStatus =
      isolated("Status") {
        val s = AgentStatus()
        synchronized(mutex) {
          s.state = stateLocked()
          if (started && !closed) {
            s.uptime = Duration.between(startedAt, Instant.now())
          }
          s.eventsSent = eventsSent
          s.eventsFailed = eventsFailed
          s.bufferSize = events.size + metrics.size
          s.lastFlush = if (lastFlush == Instant.EPOCH) null else lastFlush
          s.errors = lastErrors.toList()
          s.circuitState = tr.breaker.state()
        }
        s
      }

  /**
   * agent.go `Healthy`: whether the agent is running and not degraded by the stricter health
   * thresholds: circuit breaker open, 95% buffer occupancy, or a 50% lifetime failure rate each
   * fail the check.
   */
  public fun healthy(): Boolean =
      isolated("Healthy") {
        synchronized(mutex) {
          if (!started || closed) {
            return@isolated false
          }
          if (tr.breaker.open()) {
            return@isolated false
          }
          if ((events.size + metrics.size) >= cfg.bufferSize * HEALTH_BUFFER_RATIO) {
            return@isolated false
          }
          val total = eventsSent + eventsFailed
          if (total > 0 && eventsFailed.toDouble() / total.toDouble() > HEALTH_FAILURE_RATE_MAX) {
            return@isolated false
          }
          true
        }
      }

  /** agent.go `Stats`: lifetime counters and the circuit breaker state. */
  public fun stats(): AgentStatsSnapshot =
      isolated("Stats") {
        val s = AgentStatsSnapshot()
        synchronized(mutex) {
          s.eventsBuffered = eventsBuffered
          s.metricsBuffered = metricsBuffered
          s.eventsFlushed = eventsFlushed
          s.metricsFlushed = metricsFlushed
          s.eventsSent = eventsSent
          s.metricsSent = metricsSent
          s.eventsFailed = eventsFailed
          s.metricsFailed = metricsFailed
          s.eventsDropped = eventsDropped
          s.metricsDropped = metricsDropped
          s.eventsPending = events.size
          s.metricsPending = metrics.size
          s.redisPersistFailures = redisPersistFailures
          s.durabilityDegraded = persist != null && redisPersistFailures > 0
          s.statusReportsSent = statusSent
          s.statusReportsFailed = statusFailed
          s.rulesFetched = rulesFetched
          s.requestsSent = tr.requestsSent.get()
          s.requestsFailed = tr.requestsFailed.get()
          s.circuitState = tr.breaker.state()
        }
        s
      }

  /**
   * agent.go `AgentStats`: renders the reference get_stats dict shape (guard_agent
   * _client_status.py get_stats) for the engine's middleware agent_stats merge. Every key carries
   * the same value as the typed snapshots; the reference's per-loop consecutive-failure counters
   * (loop_failures) and last_status_push_ok have no tracked counterpart in this port and are
   * omitted.
   */
  public fun agentStats(): Map<String, Any?> {
    val stats = stats()
    var running = false
    var uptime = 0.0
    var cachedRulesFlag = false
    var rulesStamp: String? = null
    synchronized(mutex) {
      running = started && !closed
      if (running) {
        uptime = Duration.between(startedAt, Instant.now()).toMillis() / 1000.0
      }
      cachedRulesFlag = cachedRules != null
      rulesStamp = if (rulesLastUpdate != Instant.EPOCH) rfc3339Nano(rulesLastUpdate) else null
    }
    return linkedMapOf(
        "running" to running,
        "uptime" to uptime,
        "events_sent" to stats.eventsSent,
        "metrics_sent" to stats.metricsSent,
        "events_failed" to stats.eventsFailed,
        "metrics_failed" to stats.metricsFailed,
        "rules_fetched" to stats.rulesFetched,
        "buffer_stats" to
            linkedMapOf<String, Any?>(
                "events_buffered" to stats.eventsBuffered,
                "metrics_buffered" to stats.metricsBuffered,
                "events_flushed" to stats.eventsFlushed,
                "metrics_flushed" to stats.metricsFlushed,
                "events_dropped" to stats.eventsDropped,
                "metrics_dropped" to stats.metricsDropped,
                "current_event_buffer_size" to stats.eventsPending,
                "current_metric_buffer_size" to stats.metricsPending,
                "redis_persist_failures" to stats.redisPersistFailures,
                "durability_degraded" to stats.durabilityDegraded,
            ),
        "transport_stats" to
            linkedMapOf<String, Any?>(
                "requests_sent" to stats.requestsSent,
                "requests_failed" to stats.requestsFailed,
                "circuit_breaker_state" to stats.circuitState,
            ),
        "cached_rules" to cachedRulesFlag,
        "rules_last_update" to rulesStamp,
    )
  }

  // ---------------------------------------------------------- dynamic rules --

  /**
   * agent.go `GetDynamicRules`: returns the SaaS dynamic rules, serving them from the in-memory
   * cache while the rules document TTL has not expired. On a fetch failure the cached rules
   * (possibly null) are returned with no error, mirroring the Python RulesMixin.get_dynamic_rules:
   * the engine must never see a rules outage as a hard failure. Every successful refresh bumps the
   * rules_fetched stat.
   */
  public fun getDynamicRules(ctx: AgentContext = AgentContext.NONE): DynamicRules? =
      isolated("GetDynamicRules") {
        var cached: DynamicRules? = null
        synchronized(mutex) {
          cached = cachedRules
          if (
              cached != null &&
                  Duration.between(rulesLastUpdate, Instant.now()) <
                      Duration.ofSeconds(cached!!.ttl.toLong())
          ) {
            return@isolated cached
          }
        }

        val (fetched, fetchErr) = fetchRulesSafely(ctx)
        if (fetchErr != null) {
          logger.warning("guardagent: failed to fetch dynamic rules: $fetchErr")
          synchronized(mutex) {
            return@isolated cachedRules
          }
        }
        if (fetched != null) {
          synchronized(mutex) {
            cachedRules = fetched
            rulesLastUpdate = Instant.now()
            rulesFetched++
          }
        }
        fetched
      }

  /**
   * agent.go `fetchRulesSafely`: converts a transport panic into an error so the rules path keeps
   * the agent-wide failure isolation guarantee.
   */
  internal fun fetchRulesSafelyForTest(ctx: AgentContext): Pair<DynamicRules?, Throwable?> =
      fetchRulesSafely(ctx)

  private fun fetchRulesSafely(ctx: AgentContext): Pair<DynamicRules?, Throwable?> =
      try {
        tr.fetchDynamicRules(ctx)
      } catch (panic: Throwable) {
        logger.warning("guardagent: recovered from panic during dynamic rules fetch: $panic")
        null to
            GuardAgentException(
                "${Err.INTERNAL} during dynamic rules fetch: $panic",
                ErrorKind.INTERNAL,
            )
      }

  // ---------------------------------------------------------------- loops --

  private fun spawnLoop(
      name: String,
      body: () -> Unit,
  ) {
    val thread =
        Thread(
            {
              try {
                body()
              } finally {
                synchronized(mutex) { loopThreads.remove(Thread.currentThread()) }
              }
            },
            name,
        )
    thread.isDaemon = true
    synchronized(mutex) { loopThreads.add(thread) }
    thread.start()
  }

  private fun loopDone(): Boolean = loopContext.isDone()

  /** agent.go `loopCtx`: the loop context; never null once start ran. */
  internal fun loopCtx(): AgentContext = loopContext

  internal fun autoFlushLoop() {
    var consecutive = 0
    while (!loopDone()) {
      if (!sleepLoop(cfg.flushInterval)) {
        return
      }
      if (loopDone()) {
        return
      }
      consecutive = flushTick(consecutive)
    }
  }

  /**
   * agent.go `flushTick`: runs one periodic flush and returns the updated consecutive failure
   * count, escalating the log line once failures persist.
   */
  internal fun flushTick(consecutiveIn: Int): Int {
    val err = flush(loopContext)
    var consecutive = consecutiveIn
    if (err != null) {
      consecutive++
      if (consecutive < 3) {
        logger.warning("guardagent: periodic flush failed: $err")
      } else {
        logger.warning(
            "guardagent: periodic flush failing repeatedly ($consecutive in a row): $err",
        )
      }
      return consecutive
    }
    return 0
  }

  /**
   * agent.go `wakeFlushLoop`: performs watermark-triggered early flushes. One of
   * MaxConcurrentFlushes threads consumes each wake signal.
   */
  internal fun wakeFlushLoop() {
    while (!loopDone()) {
      val woke = flushWake.poll(200, TimeUnit.MILLISECONDS)
      if (woke != null) {
        flushIfNeeded()
      }
    }
  }

  internal fun statusLoop() {
    while (!loopDone()) {
      if (!sleepLoop(cfg.statusInterval)) {
        return
      }
      if (loopDone()) {
        return
      }
      reportStatus(loopContext)
    }
  }

  /**
   * agent.go `rulesLoop`: polls the SaaS for dynamic rules on the DynamicRuleInterval cadence.
   * Consecutive failures escalate from warning to error at the same threshold as the other loops.
   */
  internal fun rulesLoop() {
    var consecutive = 0
    while (!loopDone()) {
      if (!sleepLoop(cfg.dynamicRuleInterval)) {
        return
      }
      if (loopDone()) {
        return
      }
      val rules = getDynamicRules(loopContext)
      if (rules != null) {
        consecutive = 0
        continue
      }
      consecutive++
      if (consecutive < 3) {
        logger.warning(
            "guardagent: dynamic rules loop failed $consecutive time(s); serving last known rules",
        )
      } else {
        logger.warning(
            "guardagent: dynamic rules loop failing repeatedly ($consecutive in a row); serving last known rules",
        )
      }
    }
  }

  internal fun confirmWorker() {
    try {
      while (!confirmClosed) {
        val keys = confirmQueue.poll(500, TimeUnit.MILLISECONDS) ?: continue
        persist!!.del(keys)
      }
      // The queue was closed: drain the remaining confirmations, then exit,
      // mirroring the Go range-over-closed-channel semantics.
      while (true) {
        val keys = confirmQueue.poll() ?: break
        persist!!.del(keys)
      }
    } finally {
      workerDone.countDown()
    }
  }

  /**
   * Sleeps one loop tick in small slices so stop is observed promptly. Mirrors the Go `select {
   * case <-ctx.Done(): case <-ticker.C: }` wait.
   */
  private fun sleepLoop(interval: Duration): Boolean {
    val target = System.nanoTime() + interval.toNanos()
    while (true) {
      if (loopDone()) {
        return false
      }
      val remaining = target - System.nanoTime()
      if (remaining <= 0) {
        return true
      }
      try {
        Thread.sleep(Math.min(remaining, 20_000_000L) / 1_000_000)
      } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        return false
      }
    }
  }

  // -------------------------------------------------------------- enqueue --

  private fun enqueueEvent(
      ctx: AgentContext,
      ev: SecurityEvent,
  ) {
    while (true) {
      var action = 0 // 0 = block-and-retry, 1 = buffered, 2 = drop handled
      var evicted: BufferedEvent? = null
      var droppedCount = 0L
      var needFlush = false
      var item: BufferedEvent? = null
      synchronized(mutex) {
        if (events.size < cfg.bufferSize) {
          item = appendEventLocked(ev)
          needFlush = watermarkReachedLocked()
          action = 1
        } else {
          when (cfg.overflow) {
            OverflowPolicy.RAISE -> throw BufferFullError(KIND_EVENT, cfg.bufferSize)
            OverflowPolicy.DROP -> {
              val old = events.removeFirst()
              eventsDropped++
              droppedCount = eventsDropped
              item = appendEventLocked(ev)
              needFlush = watermarkReachedLocked()
              evicted = old
              action = 2
            }
            OverflowPolicy.BLOCK,
            null -> {}
          }
        }
      }
      when (action) {
        1 -> {
          spawnPersistEvent(item!!)
          if (needFlush) {
            triggerFlush()
          }
          return
        }
        2 -> {
          spawnPersistEvent(item!!)
          logDrop(KIND_EVENT, droppedCount)
          evicted?.key?.takeIf { it.isNotEmpty() }?.let { confirmKeys(listOf(it)) }
          if (needFlush) {
            triggerFlush()
          }
          return
        }
        else -> blockWait(ctx)
      }
    }
  }

  private fun enqueueMetric(
      ctx: AgentContext,
      m: SecurityMetric,
  ) {
    while (true) {
      var action = 0
      var evicted: BufferedMetric? = null
      var droppedCount = 0L
      var needFlush = false
      var item: BufferedMetric? = null
      synchronized(mutex) {
        if (metrics.size < cfg.bufferSize) {
          item = appendMetricLocked(m)
          needFlush = watermarkReachedLocked()
          action = 1
        } else {
          when (cfg.overflow) {
            OverflowPolicy.RAISE -> throw BufferFullError(KIND_METRIC, cfg.bufferSize)
            OverflowPolicy.DROP -> {
              val old = metrics.removeFirst()
              metricsDropped++
              droppedCount = metricsDropped
              item = appendMetricLocked(m)
              needFlush = watermarkReachedLocked()
              evicted = old
              action = 2
            }
            OverflowPolicy.BLOCK,
            null -> {}
          }
        }
      }
      when (action) {
        1 -> {
          spawnPersistMetric(item!!)
          if (needFlush) {
            triggerFlush()
          }
          return
        }
        2 -> {
          spawnPersistMetric(item!!)
          logDrop(KIND_METRIC, droppedCount)
          evicted?.key?.takeIf { it.isNotEmpty() }?.let { confirmKeys(listOf(it)) }
          if (needFlush) {
            triggerFlush()
          }
          return
        }
        else -> blockWait(ctx)
      }
    }
  }

  /**
   * agent.go block-policy wait: the Go select over flushSignal (the 500ms poll interval) and
   * ctx.Done.
   */
  private fun blockWait(ctx: AgentContext) {
    val deadline = System.nanoTime() + BLOCK_POLL_INTERVAL.toNanos()
    while (!ctx.isDone()) {
      val remaining = deadline - System.nanoTime()
      if (remaining <= 0) {
        return
      }
      val woke = flushSignal.poll(Math.min(remaining, 20_000_000L), TimeUnit.NANOSECONDS)
      if (woke != null) {
        return
      }
    }
    throw ctx.err()
  }

  /**
   * agent.go `appendEventLocked`: appends under a held lock. Redis is never touched here: the
   * caller hands the returned item to [spawnPersistEvent] after releasing the lock.
   */
  private fun appendEventLocked(ev: SecurityEvent): BufferedEvent {
    // The key is minted here, under the lock, so key order equals append order (reload sorts keys).
    val item = BufferedEvent(ev, "", mintKey(PERSIST_NAMESPACE_EVENTS, "event"))
    events.add(item)
    eventsBuffered++
    return item
  }

  private fun appendMetricLocked(m: SecurityMetric): BufferedMetric {
    val item = BufferedMetric(m, "", mintKey(PERSIST_NAMESPACE_METRICS, "metric"))
    metrics.add(item)
    metricsBuffered++
    return item
  }

  private fun mintKey(
      namespace: String,
      kind: String,
  ): String = persist?.let { it.fullKey(namespace, it.shortKey(kind)) } ?: ""

  private fun watermarkReachedLocked(): Boolean {
    val combined = events.size + metrics.size
    return combined.toDouble() >= cfg.bufferSize.toDouble() * cfg.highWatermarkRatio
  }

  /** Runs [task] on the persist pool; a full or closed pool skips persistence (fail-open). */
  private fun submitPersist(task: () -> Unit) {
    val pool = persistPool ?: return
    try {
      pool.execute {
        try {
          task()
        } catch (e: Throwable) {
          logger.warning("guardagent: redis persist task failed: $e")
        }
      }
    } catch (e: java.util.concurrent.RejectedExecutionException) {
      synchronized(mutex) { redisPersistFailures++ }
    }
  }

  private fun spawnPersistEvent(item: BufferedEvent) = submitPersist { persistEventNow(item) }

  private fun spawnPersistMetric(item: BufferedMetric) = submitPersist { persistMetricNow(item) }

  /** Persists one buffered event and settles its key. Never called with [mutex] held. */
  internal fun persistEventNow(item: BufferedEvent) {
    val data =
        try {
          goJson(item.ev)
        } catch (err: Exception) {
          synchronized(mutex) {
            redisPersistFailures++
            recordErrorLocked("event serialization for persistence failed: ${err.message}")
          }
          return
        }
    val key =
        persistItem(item.reserved.ifEmpty { mintKey(PERSIST_NAMESPACE_EVENTS, "event") }, data)
    if (key.isEmpty()) {
      return
    }
    // Still buffered (including after a requeue): track the key. Flushed or evicted before
    // the key came back: delete it so it neither orphans nor replays after a restart.
    val tracked =
        synchronized(mutex) {
          val buffered = events.asReversed().any { it === item }
          if (buffered) item.key = key
          buffered
        }
    if (!tracked) {
      confirmKeys(listOf(key))
    }
  }

  /** Metric twin of [persistEventNow]. */
  internal fun persistMetricNow(item: BufferedMetric) {
    val key =
        persistItem(
            item.reserved.ifEmpty { mintKey(PERSIST_NAMESPACE_METRICS, "metric") },
            goJson(item.m),
        )
    if (key.isEmpty()) {
      return
    }
    val tracked =
        synchronized(mutex) {
          val buffered = metrics.asReversed().any { it === item }
          if (buffered) item.key = key
          buffered
        }
    if (!tracked) {
      confirmKeys(listOf(key))
    }
  }

  /** Writes one record to Redis. Must be called WITHOUT [mutex] held. */
  private fun persistItem(
      key: String,
      data: ByteArray,
  ): String {
    val p = persist!!
    if (p.store(key, data.toString(Charsets.UTF_8))) {
      return key
    }
    synchronized(mutex) { redisPersistFailures++ }
    return ""
  }

  private fun logDrop(
      kind: String,
      dropped: Long,
  ) {
    if (dropped % DROP_LOG_INTERVAL == 1L) {
      logger.warning(
          "guardagent: $kind buffer overflow (drop policy): $dropped total drop(s) so far",
      )
    }
  }

  // ---------------------------------------------------------------- flush --

  /**
   * agent.go `triggerFlush`: wakes a flusher thread when the high-watermark is reached. The wake
   * queue is non-blocking: at most one early flush is ever pending, mirroring the Python agent's
   * in-flight flush semaphore.
   */
  internal fun triggerFlush() {
    flushWake.offer(wakeToken)
  }

  /**
   * agent.go `flushIfNeeded`: mirrors _flush_if_needed: fire when the combined occupancy reaches
   * the watermark, when the flush interval elapsed since the last drain, or when nothing was ever
   * flushed and the buffer is non-empty.
   */
  internal fun flushIfNeeded() {
    var shouldFlush: Boolean
    synchronized(mutex) {
      val combined = events.size + metrics.size
      if (combined == 0) {
        return
      }
      val watermarkOK = combined.toDouble() >= cfg.bufferSize.toDouble() * cfg.highWatermarkRatio
      val elapsedOK =
          lastFlush == Instant.EPOCH ||
              Duration.between(lastFlush, Instant.now()) >= cfg.flushInterval
      shouldFlush = watermarkOK || elapsedOK
    }
    if (shouldFlush) {
      flush(loopContext)
    }
  }

  internal fun flushEvents(
      ctx: AgentContext,
      force: Boolean,
  ): Throwable? {
    if (!cfg.enableEvents) {
      return null
    }
    val drained = ArrayList<BufferedEvent>()
    val keys = ArrayList<String>()
    synchronized(mutex) {
      if (!force && gateClosedLocked(eventGate)) {
        return null
      }
      if (events.isEmpty()) {
        return null
      }
      drained.addAll(events)
      events.clear()
      eventsFlushed += drained.size
      for (item in drained) {
        if (item.key.isNotEmpty()) {
          keys.add(item.key)
        }
      }
      lastFlush = Instant.now()
      signalSpaceLocked()
    }
    val items = drained.map { it.ev }
    val (outcome, err) = sendEventsSafely(ctx, items)
    return settleEvents(drained, keys, outcome, err)
  }

  /**
   * agent.go `sendEventsSafely`: converts a transport panic into outcomeFailed so the handshake
   * still runs and the batch is requeued, never lost.
   */
  private fun sendEventsSafely(
      ctx: AgentContext,
      items: List<SecurityEvent>,
  ): Pair<SendOutcome, Throwable?> =
      try {
        tr.sendEvents(ctx, items)
      } catch (panic: Throwable) {
        logger.warning("guardagent: recovered from panic during event send: $panic")
        SendOutcome.FAILED to
            GuardAgentException("${Err.INTERNAL} during event send: $panic", ErrorKind.INTERNAL)
      }

  internal fun flushMetrics(
      ctx: AgentContext,
      force: Boolean,
  ): Throwable? {
    if (!cfg.enableMetrics) {
      return null
    }
    val drained = ArrayList<BufferedMetric>()
    val keys = ArrayList<String>()
    synchronized(mutex) {
      if (!force && gateClosedLocked(metricGate)) {
        return null
      }
      if (metrics.isEmpty()) {
        return null
      }
      drained.addAll(metrics)
      metrics.clear()
      metricsFlushed += drained.size
      for (item in drained) {
        if (item.key.isNotEmpty()) {
          keys.add(item.key)
        }
      }
      lastFlush = Instant.now()
      signalSpaceLocked()
    }
    val items = drained.map { it.m }
    val (outcome, err) = sendMetricsSafely(ctx, items)
    return settleMetrics(drained, keys, outcome, err)
  }

  private fun sendMetricsSafely(
      ctx: AgentContext,
      items: List<SecurityMetric>,
  ): Pair<SendOutcome, Throwable?> =
      try {
        tr.sendMetrics(ctx, items)
      } catch (panic: Throwable) {
        logger.warning("guardagent: recovered from panic during metric send: $panic")
        SendOutcome.FAILED to
            GuardAgentException("${Err.INTERNAL} during metric send: $panic", ErrorKind.INTERNAL)
      }

  /**
   * agent.go `settleEvents`: the confirm/requeue half of the at-least-once handshake: accepted and
   * permanent outcomes confirm the persisted records; partial and failed outcomes requeue the
   * drained batch in its original order and arm the per-kind backoff gate.
   */
  private fun settleEvents(
      drained: List<BufferedEvent>,
      keys: List<String>,
      outcome: SendOutcome,
      errIn: Throwable?,
  ): Throwable? {
    var err = errIn
    when (outcome) {
      SendOutcome.ACCEPTED -> {
        confirmKeys(keys)
        synchronized(mutex) {
          eventsSent += drained.size
          if (eventStreak > 0) {
            logger.warning(
                "guardagent: event flush recovered after $eventStreak consecutive failure(s)",
            )
          }
          eventStreak = 0
          eventGate = Instant.EPOCH
        }
        return null
      }
      SendOutcome.PERMANENT -> {
        confirmKeys(keys)
        synchronized(mutex) {
          eventsSent += drained.size
          recordErrorLocked("${drained.size} event(s) permanently rejected by ingestion API")
        }
        logger.warning(
            "guardagent: ${drained.size} event(s) permanently rejected by ingestion API; dropped durably",
        )
        fireErrorHook(
            cfg.onError,
            logger,
            ErrorHookStages.TRANSPORT_SEND,
            err,
            mapOf("data_type" to "events", "item_count" to drained.size),
        )
        return null
      }
      else -> {
        var streak: Int
        var delay: Duration
        synchronized(mutex) {
          eventsFailed += drained.size
          eventStreak++
          delay = partialFailureBackoff(eventStreak, cfg.flushInterval)
          eventGate = Instant.now().plus(delay)
          streak = eventStreak
        }
        if (streak == 1) {
          logger.warning(
              "guardagent: event flush failed; pausing event flushes for $delay: $err",
          )
        }
        requeueEvents(drained)
        if (err == null) {
          err = GuardAgentException("guardagent: event flush failed", ErrorKind.INTERNAL)
        }
        fireErrorHook(
            cfg.onError,
            logger,
            ErrorHookStages.FLUSH_EVENTS,
            err,
            mapOf("batch_size" to drained.size),
        )
        return err
      }
    }
  }

  private fun settleMetrics(
      drained: List<BufferedMetric>,
      keys: List<String>,
      outcome: SendOutcome,
      errIn: Throwable?,
  ): Throwable? {
    var err = errIn
    when (outcome) {
      SendOutcome.ACCEPTED -> {
        confirmKeys(keys)
        synchronized(mutex) {
          metricsSent += drained.size
          if (metricStreak > 0) {
            logger.warning(
                "guardagent: metric flush recovered after $metricStreak consecutive failure(s)",
            )
          }
          metricStreak = 0
          metricGate = Instant.EPOCH
        }
        return null
      }
      SendOutcome.PERMANENT -> {
        confirmKeys(keys)
        synchronized(mutex) {
          metricsSent += drained.size
          recordErrorLocked("${drained.size} metric(s) permanently rejected by ingestion API")
        }
        logger.warning(
            "guardagent: ${drained.size} metric(s) permanently rejected by ingestion API; dropped durably",
        )
        fireErrorHook(
            cfg.onError,
            logger,
            ErrorHookStages.TRANSPORT_SEND,
            err,
            mapOf("data_type" to "metrics", "item_count" to drained.size),
        )
        return null
      }
      else -> {
        var streak: Int
        var delay: Duration
        synchronized(mutex) {
          metricsFailed += drained.size
          metricStreak++
          delay = partialFailureBackoff(metricStreak, cfg.flushInterval)
          metricGate = Instant.now().plus(delay)
          streak = metricStreak
        }
        if (streak == 1) {
          logger.warning(
              "guardagent: metric flush failed; pausing metric flushes for $delay: $err",
          )
        }
        requeueMetrics(drained)
        if (err == null) {
          err = GuardAgentException("guardagent: metric flush failed", ErrorKind.INTERNAL)
        }
        fireErrorHook(
            cfg.onError,
            logger,
            ErrorHookStages.FLUSH_METRICS,
            err,
            mapOf("batch_size" to drained.size),
        )
        return err
      }
    }
  }

  /**
   * agent.go `requeueEvents`: pushes the drained batch back to the FRONT of the buffer in its
   * original order. Under pressure the TAIL (newest buffered items) is evicted, mirroring
   * guard-agent (Python) appendleft-into-maxlen-deque.
   */
  internal fun requeueEvents(items: List<BufferedEvent>) {
    val orphaned = mutableListOf<String>()
    var dropped = 0
    synchronized(mutex) {
      val merged = ArrayList<BufferedEvent>(items.size + events.size)
      merged.addAll(items)
      merged.addAll(events)
      while (merged.size > cfg.bufferSize) {
        val tail = merged.removeAt(merged.size - 1)
        dropped++
        if (tail.key.isNotEmpty()) {
          orphaned.add(tail.key)
        }
      }
      events.clear()
      events.addAll(merged)
      if (dropped > 0) {
        eventsDropped += dropped
      }
      signalSpaceLocked()
    }
    if (dropped > 0) {
      logger.warning(
          "guardagent: buffer pressure during event requeue evicted $dropped newest buffered event(s)",
      )
    }
    confirmKeys(orphaned)
  }

  internal fun requeueMetrics(items: List<BufferedMetric>) {
    val orphaned = mutableListOf<String>()
    var dropped = 0
    synchronized(mutex) {
      val merged = ArrayList<BufferedMetric>(items.size + metrics.size)
      merged.addAll(items)
      merged.addAll(metrics)
      while (merged.size > cfg.bufferSize) {
        val tail = merged.removeAt(merged.size - 1)
        dropped++
        if (tail.key.isNotEmpty()) {
          orphaned.add(tail.key)
        }
      }
      metrics.clear()
      metrics.addAll(merged)
      if (dropped > 0) {
        metricsDropped += dropped
      }
      signalSpaceLocked()
    }
    if (dropped > 0) {
      logger.warning(
          "guardagent: buffer pressure during metric requeue evicted $dropped newest buffered metric(s)",
      )
    }
    confirmKeys(orphaned)
  }

  private fun gateClosedLocked(gate: Instant): Boolean =
      gate != Instant.EPOCH && Instant.now().isBefore(gate)

  private fun signalSpaceLocked() {
    flushSignal.offer(wakeToken)
  }

  // --------------------------------------------------------------- status --

  internal fun reportStatus(ctx: AgentContext) {
    val payload = statusPayload()
    val (outcome, err) =
        try {
          tr.sendStatus(ctx, payload)
        } catch (panic: Throwable) {
          logger.warning("guardagent: recovered from panic during status send: $panic")
          SendOutcome.FAILED to
              GuardAgentException("${Err.INTERNAL} during status send: $panic", ErrorKind.INTERNAL)
        }
    synchronized(mutex) {
      when (outcome) {
        SendOutcome.ACCEPTED,
        SendOutcome.PERMANENT -> {
          statusSent++
          statusStreak = 0
        }
        else -> {
          statusFailed++
          statusStreak++
          val detail =
              if (err != null) {
                "status report failed: $err"
              } else {
                "status report failed"
              }
          recordErrorLocked(detail)
          logger.warning("guardagent: $detail")
        }
      }
    }
  }

  internal fun statusPayload(): AgentStatusPayload {
    synchronized(mutex) {
      val payload = AgentStatusPayload()
      payload.timestamp = Instant.now()
      payload.status = stateLocked()
      payload.eventsSent = eventsSent
      payload.eventsFailed = eventsFailed
      payload.bufferSize = events.size + metrics.size
      payload.errors = lastErrors.toList()
      if (started && !closed) {
        payload.uptime = Duration.between(startedAt, Instant.now()).toMillis() / 1000.0
      }
      if (lastFlush != Instant.EPOCH) {
        payload.lastFlush = lastFlush
      }
      return payload
    }
  }

  private fun stateLocked(): String {
    if (closed) {
      return AgentStatusValues.FAILED
    }
    if (tr.breaker.open()) {
      return AgentStatusValues.DEGRADED
    }
    if (
        (events.size + metrics.size).toDouble() >= cfg.bufferSize.toDouble() * DEGRADED_BUFFER_RATIO
    ) {
      return AgentStatusValues.DEGRADED
    }
    val total = eventsSent + eventsFailed
    if (total > 0 && eventsFailed.toDouble() / total.toDouble() > DEGRADED_FAILURE_RATE) {
      return AgentStatusValues.DEGRADED
    }
    return AgentStatusValues.HEALTHY
  }

  internal fun recordErrorLocked(msg: String) {
    lastErrors.add(msg)
    while (lastErrors.size > MAX_TRACKED_ERRORS) {
      lastErrors.removeAt(0)
    }
  }

  // ------------------------------------------------------------ lifecycle --

  private fun guardClosed() {
    synchronized(mutex) {
      if (closed) {
        throw GuardAgentException(Err.CLOSED, ErrorKind.CLOSED)
      }
    }
  }

  /**
   * agent.go `confirmKeys`: queues persisted records for deletion on the confirm worker. Deletion
   * is best effort: the TTL is the backstop, so a dropped confirmation at worst causes a duplicate
   * reload after a crash, never a loss.
   */
  internal fun confirmKeys(keys: List<String>) {
    val p = persist ?: return
    if (keys.isEmpty()) {
      return
    }
    if (confirmClosed || !confirmQueue.offer(keys)) {
      // The confirm worker is unavailable or its queue is full: delete
      // directly (Go's default branch, and the recovered send on a closed
      // channel).
      try {
        p.del(keys)
      } catch (panic: Throwable) {
        logger.warning(
            "guardagent: confirm worker unavailable, ${keys.size} record(s) left to TTL expiry",
        )
      }
    }
  }

  /**
   * agent.go `reloadFromRedisLocked`: restores persisted telemetry buffered before a previous run.
   * Items are applied oldest first, keeping the newest when over capacity; evicted and corrupt
   * records are deleted so a later restart cannot resurrect them.
   */
  private fun reloadFromRedisLocked() {
    val p = persist!!
    reloadKindLocked(p, PERSIST_NAMESPACE_EVENTS) { short, value, fullKey ->
      val ev =
          try {
            securityEventFromJson(value.toByteArray(Charsets.UTF_8))
          } catch (err: Exception) {
            logger.warning("guardagent: dropping corrupt persisted event $short: ${err.message}")
            p.del(listOf(fullKey))
            return@reloadKindLocked
          }
      if (events.size >= cfg.bufferSize) {
        val head = events.removeFirst()
        if (head.key.isNotEmpty()) {
          p.del(listOf(head.key))
        }
      }
      events.add(BufferedEvent(ev, fullKey))
      eventsBuffered++
    }
    reloadKindLocked(p, PERSIST_NAMESPACE_METRICS) { short, value, fullKey ->
      val m =
          try {
            securityMetricFromJson(value.toByteArray(Charsets.UTF_8))
          } catch (err: Exception) {
            logger.warning("guardagent: dropping corrupt persisted metric $short: ${err.message}")
            p.del(listOf(fullKey))
            return@reloadKindLocked
          }
      if (metrics.size >= cfg.bufferSize) {
        val head = metrics.removeFirst()
        if (head.key.isNotEmpty()) {
          p.del(listOf(head.key))
        }
      }
      metrics.add(BufferedMetric(m, fullKey))
      metricsBuffered++
    }
  }

  private inline fun reloadKindLocked(
      p: Persistence,
      namespace: String,
      apply: (short: String, value: String, fullKey: String) -> Unit,
  ) {
    val items =
        try {
          p.loadKind(namespace)
        } catch (err: Exception) {
          logger.warning(
              "guardagent: redis reload for $namespace failed, starting memory-only: ${err.message}",
          )
          redisPersistFailures++
          return
        }
    for (item in items) {
      apply(item.short, item.value, p.fullKey(namespace, item.short))
    }
    if (items.isNotEmpty()) {
      logger.warning(
          "guardagent: reloaded ${items.size} persisted $namespace record(s) from redis",
      )
    }
  }

  /**
   * agent.go `recoverPanic`: converts an unexpected throwable in an exported method into a logged
   * ErrInternal, implementing the failure isolation policy: telemetry must never take down the host
   * application. Known agent errors pass through unchanged (they are the API's error returns).
   */
  private inline fun <T> isolated(
      method: String,
      block: () -> T,
  ): T =
      try {
        block()
      } catch (known: ContextDone) {
        throw known
      } catch (known: GuardAgentException) {
        throw known
      } catch (known: AgentConfigException) {
        throw known
      } catch (known: EncryptionError) {
        throw known
      } catch (known: EncryptionConfigError) {
        throw known
      } catch (known: SerializationError) {
        throw known
      } catch (panic: Throwable) {
        logger.warning("guardagent: recovered from panic in $method: $panic")
        throw GuardAgentException("${Err.INTERNAL} in $method: $panic", ErrorKind.INTERNAL)
      }

  private fun joinErrors(
      a: Throwable?,
      b: Throwable?,
  ): Throwable? =
      when {
        a == null && b == null -> null
        a != null && b != null -> JoinedErrors(listOf(a, b))
        else -> a ?: b
      }
}
