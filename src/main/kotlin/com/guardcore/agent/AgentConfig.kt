package com.guardcore.agent

import java.net.URI
import java.time.Duration
import java.util.logging.Logger

/**
 * Port of guard-agent-go `config.go`: configuration keys, defaults, env overrides live with the
 * host, and the normalize validator (mirroring guard-agent (Python) models.py field validators plus
 * utils.validate_config).
 */

/** The Guard Core App ingestion base URL used when endpoint is empty. */
public const val DEFAULT_ENDPOINT: String = "https://api.guard-core.com"

// Defaults applied by GuardAgent.create when the corresponding field is zero.
internal const val DEFAULT_BUFFER_SIZE: Int = 100
internal val DEFAULT_FLUSH_INTERVAL: Duration = Duration.ofSeconds(30)
internal val DEFAULT_STATUS_INTERVAL: Duration = Duration.ofSeconds(300)
internal val DEFAULT_TIMEOUT: Duration = Duration.ofSeconds(30)
internal const val DEFAULT_BACKOFF_FACTOR: Double = 1.0
internal const val DEFAULT_HIGH_WATERMARK: Double = 0.8
internal const val DEFAULT_MAX_CONCURRENT: Int = 1
internal const val DEFAULT_RETRY_ATTEMPTS: Int = 3
internal const val DEFAULT_COMPRESS_THRESH: Int = 1024
internal const val DEFAULT_REDIS_PREFIX: String = "guard:agent"
internal val DEFAULT_PERSIST_TTL: Duration = Duration.ofSeconds(3600)
internal const val DEFAULT_MAX_PAYLOAD_SIZE: Int = 1024
private const val MIN_API_KEY_LENGTH: Int = 10
private val MIN_STATUS_INTERVAL: Duration = Duration.ofSeconds(60)
private val MIN_DYNAMIC_RULE_INTERVAL: Duration = Duration.ofSeconds(60)
private val DEFAULT_RULE_INTERVAL: Duration = Duration.ofSeconds(300)
private const val API_VERSION_PATH_SUFFIX: String = "/api/v1"
internal const val API_VERSION_SUFFIX_WARNING: String =
    "endpoint ends with /api/v1; the agent appends API paths itself, so the suffix was removed"

/**
 * OverflowPolicy selects the behavior of sendEvent and sendMetric when the per-kind buffer is full.
 * It is a string type exactly like the Go enum (config.go `OverflowPolicy`): the three sentinels
 * are the valid values, and arbitrary strings are constructible so the normalize validator can
 * reject them.
 */
public class OverflowPolicy(
    public val wire: String,
) {
  override fun equals(other: Any?): Boolean = other is OverflowPolicy && other.wire == wire

  override fun hashCode(): Int = wire.hashCode()

  override fun toString(): String = wire

  public companion object {
    /**
     * DROP (default) evicts the oldest buffered item of the same kind, confirms (deletes) its
     * persisted record, and counts a drop.
     */
    public val DROP: OverflowPolicy = OverflowPolicy("drop")

    /**
     * BLOCK waits for flush to free space, polling every 500ms and returning the context error when
     * the context ends. A requeued batch always keeps its slots: durability wins over a new writer.
     */
    public val BLOCK: OverflowPolicy = OverflowPolicy("block")

    /** RAISE makes sendEvent and sendMetric throw [BufferFullError] without buffering. */
    public val RAISE: OverflowPolicy = OverflowPolicy("raise")

    internal val valid = setOf("drop", "block", "raise")

    /** The sentinel for a recognized wire string; a fresh instance otherwise. */
    public fun fromWire(value: String?): OverflowPolicy? =
        when (value) {
          null -> null
          "drop" -> DROP
          "block" -> BLOCK
          "raise" -> RAISE
          else -> OverflowPolicy(value)
        }
  }
}

/**
 * RedisConfig enables optional Redis durability for buffered telemetry. Records are written on
 * enqueue with a TTL, deleted on confirmation, and reloaded on start, so a crash between enqueue
 * and confirmation does not lose telemetry. Every Redis failure is fail-open: the agent logs and
 * counts the failure and keeps operating from memory.
 */
public class RedisConfig {
  /** A redis:// or rediss:// connection string. */
  public var url: String = ""

  /**
   * Prefix namespaces every key; default "guard:agent". Keys are "{Prefix}:{namespace}:{short-key}"
   * with namespaces "agent_events" and "agent_metrics".
   */
  public var prefix: String = ""

  /** TTL bounds record lifetime; default 1 hour. */
  public var ttl: Duration = Duration.ZERO

  public constructor()

  public constructor(
      url: String,
      prefix: String = "",
      ttl: Duration = Duration.ZERO,
  ) {
    this.url = url
    this.prefix = prefix
    this.ttl = ttl
  }
}

/** The error callback signature (config.go `OnError`). */
public fun interface OnErrorHook {
  /**
   * Invoked when a transport, encryption, or flush step fails. The first argument is the stage, one
   * of the [ErrorHookStages] constants; the second is the error (null when a split-or-drop verdict
   * carries none, exactly like the Go hook); the third is a small context map.
   */
  public fun onError(
      stage: String,
      err: Throwable?,
      context: Map<String, Any?>,
  )
}

/**
 * Configures a [GuardAgent]. Start from [defaultConfig] and override what you need. Booleans are
 * explicit: the default value of enableEvents, enableMetrics, and compressionEnabled is false, so a
 * hand-built config that omits them disables that feature; [defaultConfig] turns them on.
 */
public class AgentConfig {
  /** Authenticates against the ingestion API (X-API-Key). Required, at least 10 characters. */
  public var apiKey: String = ""

  /**
   * The ingestion base URL, default [DEFAULT_ENDPOINT]. A trailing slash and a trailing /api/v1
   * suffix are removed.
   */
  public var endpoint: String = ""

  /** Sent as X-Project-Id when non-empty. */
  public var projectId: String = ""

  /** Caps each per-kind queue; default 100. */
  public var bufferSize: Int = 0

  /** The periodic flush cadence and the base of the per-kind failure backoff; default 30s. */
  public var flushInterval: Duration = Duration.ZERO

  /** The status reporting cadence, minimum 60s, default 300s. */
  public var statusInterval: Duration = Duration.ZERO

  /**
   * The SaaS dynamic rules polling cadence, minimum 60s, default 300s. The fetched document carries
   * its own TTL that gates re-fetches inside getDynamicRules.
   */
  public var dynamicRuleInterval: Duration = Duration.ZERO

  /**
   * Triggers an early flush once the combined buffer occupancy reaches ratio * bufferSize; default
   * 0.8.
   */
  public var highWatermarkRatio: Double = 0.0

  /** Bounds in-flight flush cycles; default 1. */
  public var maxConcurrentFlushes: Int = 0

  /** Selects the full-buffer policy; default [OverflowPolicy.DROP]. */
  public var overflow: OverflowPolicy? = null

  /** Enables sendEvent; default true in [defaultConfig]. */
  public var enableEvents: Boolean = false

  /** Enables sendMetric; default true in [defaultConfig]. */
  public var enableMetrics: Boolean = false

  /**
   * The number of retries after a failed attempt. Zero disables retries (zero-honest field);
   * [defaultConfig] sets 3.
   */
  public var retryAttempts: Int = 0

  /** Bounds one HTTP request; default 30s. */
  public var timeout: Duration = Duration.ZERO

  /** The base retry delay in seconds; default 1.0. */
  public var backoffFactor: Double = 0.0

  /** Gzips bodies at or above compressionThreshold; default true in [defaultConfig]. */
  public var compressionEnabled: Boolean = false

  /**
   * The gzip cutoff in bytes. Zero compresses every body (zero-honest field); [defaultConfig]
   * sets 1024.
   */
  public var compressionThreshold: Int = 0

  /**
   * Signs payloads. When empty, no signature header is sent. The HMAC-SHA256 signature covers the
   * uncompressed JSON body.
   */
  public var signingSecret: String = ""

  /**
   * The project-specific AES-256 key (urlsafe-base64-encoded, from the core backend). When set,
   * event and metric batches are encrypted and posted to /api/v1/events/encrypted; an invalid key
   * or a failed round-trip verification fails construction (no plaintext fallback), mirroring the
   * Python agent.
   */
  public var projectEncryptionKey: String = ""

  /**
   * Header names whose values are redacted from event metadata and metric tags. Matching is
   * case-insensitive after trimming whitespace. A null list means [DEFAULT_SENSITIVE_HEADERS]; a
   * non-null list (including empty) replaces the defaults. Redaction runs twice, at capture
   * (sendEvent/sendMetric) and again at batch serialization.
   */
  public var sensitiveHeaders: List<String>? = null

  /**
   * The maximum payload size (in bytes) a host adapter should embed in an event before truncating
   * it with truncatePayload; default 1024. The agent itself never truncates caller-provided
   * payloads.
   */
  public var maxPayloadSize: Int = 0

  /**
   * An optional best-effort failure callback invoked when a transport, encryption, or flush step
   * fails. A callback that throws is recovered and logged, never propagated.
   */
  public var onError: OnErrorHook? = null

  /** Overrides the persisted install id. */
  public var installId: String = ""

  /** Overrides the install id state file, default ~/.guard-agent/install-id. */
  public var installIdPath: String = ""

  /** Enables optional persistence; null disables it. */
  public var redis: RedisConfig? = null

  /** Reported to the ingestion API as guard_version. */
  public var guardVersion: String = ""

  /** Reported to the ingestion API as guard_core_version. */
  public var guardCoreVersion: String = ""

  public constructor()

  public constructor(other: AgentConfig) {
    apiKey = other.apiKey
    endpoint = other.endpoint
    projectId = other.projectId
    bufferSize = other.bufferSize
    flushInterval = other.flushInterval
    statusInterval = other.statusInterval
    dynamicRuleInterval = other.dynamicRuleInterval
    highWatermarkRatio = other.highWatermarkRatio
    maxConcurrentFlushes = other.maxConcurrentFlushes
    overflow = other.overflow
    enableEvents = other.enableEvents
    enableMetrics = other.enableMetrics
    retryAttempts = other.retryAttempts
    timeout = other.timeout
    backoffFactor = other.backoffFactor
    compressionEnabled = other.compressionEnabled
    compressionThreshold = other.compressionThreshold
    signingSecret = other.signingSecret
    projectEncryptionKey = other.projectEncryptionKey
    sensitiveHeaders = other.sensitiveHeaders?.toList()
    maxPayloadSize = other.maxPayloadSize
    onError = other.onError
    installId = other.installId
    installIdPath = other.installIdPath
    other.redis?.let {
      redis = RedisConfig(it.url, it.prefix, it.ttl)
    }
    guardVersion = other.guardVersion
    guardCoreVersion = other.guardCoreVersion
  }
}

/**
 * Returns an [AgentConfig] with the same defaults as guard-agent (Python) AgentConfig: 100-item
 * buffers, 30s flush, 300s status, 0.8 watermark, drop overflow, 3 retries, 30s timeout, gzip at
 * 1024 bytes, events and metrics enabled.
 */
public fun defaultConfig(): AgentConfig =
    AgentConfig().apply {
      endpoint = DEFAULT_ENDPOINT
      bufferSize = DEFAULT_BUFFER_SIZE
      flushInterval = DEFAULT_FLUSH_INTERVAL
      statusInterval = DEFAULT_STATUS_INTERVAL
      highWatermarkRatio = DEFAULT_HIGH_WATERMARK
      maxConcurrentFlushes = DEFAULT_MAX_CONCURRENT
      overflow = OverflowPolicy.DROP
      enableEvents = true
      enableMetrics = true
      retryAttempts = DEFAULT_RETRY_ATTEMPTS
      timeout = DEFAULT_TIMEOUT
      backoffFactor = DEFAULT_BACKOFF_FACTOR
      compressionEnabled = true
      compressionThreshold = DEFAULT_COMPRESS_THRESH
      sensitiveHeaders = null // null means DEFAULT_SENSITIVE_HEADERS.
      maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE
      dynamicRuleInterval = DEFAULT_RULE_INTERVAL
    }

/** Construction options (config.go `Option`). */
public class AgentOptions {
  /** The logger; null falls back to the global guardagent logger. */
  public var logger: Logger? = null

  /**
   * The HTTP dispatcher; null uses the default java.net.http client. The dispatcher should not
   * follow redirects, matching the reference agents.
   */
  public var httpClient: HttpDoer? = null

  /** config.go `WithLogger`: replaces the default logger. Nil is ignored. */
  public fun withLogger(logger: Logger?): AgentOptions {
    if (logger != null) {
      this.logger = logger
    }
    return this
  }

  /** config.go `WithHTTPClient`: replaces the HTTP dispatcher. Nil is ignored. */
  public fun withHttpClient(client: HttpDoer?): AgentOptions {
    if (client != null) {
      httpClient = client
    }
    return this
  }
}

/**
 * config.go `normalize`: fills defaults and validates cfg, returning the normalized config, every
 * warning, and an [AgentConfigException] carrying every problem found.
 */
internal fun normalize(
    cfg: AgentConfig,
): NormalizedConfig {
  val problems = mutableListOf<String>()
  val warnings = mutableListOf<String>()
  val out = AgentConfig(cfg)

  if (out.apiKey.isEmpty()) {
    problems.add("api key is required")
  } else if (out.apiKey.length < MIN_API_KEY_LENGTH) {
    problems.add("api key must be at least 10 characters")
  }

  val (endpoint, endpointWarnings, endpointErr) = normalizeEndpoint(out.endpoint)
  if (endpointErr != null) {
    problems.add(endpointErr.message ?: "endpoint must be a valid URL")
  } else {
    out.endpoint = endpoint
    warnings.addAll(endpointWarnings)
  }

  if (out.bufferSize == 0) {
    out.bufferSize = DEFAULT_BUFFER_SIZE
  } else if (out.bufferSize < 0) {
    problems.add("buffer size must be greater than 0")
  }

  if (out.flushInterval.isZero) {
    out.flushInterval = DEFAULT_FLUSH_INTERVAL
  } else if (out.flushInterval.isNegative) {
    problems.add("flush interval must be greater than 0")
  }

  if (out.statusInterval.isZero) {
    out.statusInterval = DEFAULT_STATUS_INTERVAL
  } else if (out.statusInterval < MIN_STATUS_INTERVAL) {
    problems.add("status interval must be at least 60s")
  }

  if (out.dynamicRuleInterval.isZero) {
    out.dynamicRuleInterval = DEFAULT_RULE_INTERVAL
  } else if (out.dynamicRuleInterval < MIN_DYNAMIC_RULE_INTERVAL) {
    problems.add("dynamic rule interval must be at least 60s")
  }

  if (out.highWatermarkRatio == 0.0) {
    out.highWatermarkRatio = DEFAULT_HIGH_WATERMARK
  } else if (out.highWatermarkRatio < 0 || out.highWatermarkRatio > 1) {
    problems.add("high watermark ratio must be in (0, 1]")
  }

  if (out.maxConcurrentFlushes == 0) {
    out.maxConcurrentFlushes = DEFAULT_MAX_CONCURRENT
  } else if (out.maxConcurrentFlushes < 0) {
    problems.add("max concurrent flushes must be at least 1")
  }

  val overflow = out.overflow
  if (overflow == null) {
    out.overflow = OverflowPolicy.DROP
  } else if (overflow.wire !in OverflowPolicy.valid) {
    problems.add("overflow policy must be one of \"drop\", \"block\", \"raise\"")
  }

  // RetryAttempts is zero-honest: 0 disables retries, so it is NOT
  // default-filled. DefaultConfig sets 3.
  if (out.retryAttempts < 0) {
    problems.add("retry attempts must be 0 or greater")
  }

  if (out.timeout.isZero) {
    out.timeout = DEFAULT_TIMEOUT
  } else if (out.timeout.isNegative) {
    problems.add("timeout must be greater than 0")
  }

  if (out.backoffFactor == 0.0) {
    out.backoffFactor = DEFAULT_BACKOFF_FACTOR
  } else if (out.backoffFactor < 0) {
    problems.add("backoff factor must be greater than 0")
  }

  // CompressionThreshold is zero-honest: 0 compresses every body, so it is
  // NOT default-filled. DefaultConfig sets 1024.
  if (out.compressionThreshold < 0) {
    problems.add("compression threshold must be 0 or greater")
  }

  if (out.maxPayloadSize == 0) {
    out.maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE
  } else if (out.maxPayloadSize < 0) {
    problems.add("max payload size must be greater than 0")
  }

  out.sensitiveHeaders = normalizeSensitiveHeaders(out.sensitiveHeaders)

  if (out.installIdPath.isEmpty()) {
    out.installIdPath = defaultInstallIDPath()
  }

  out.redis?.let { redis ->
    if (redis.url.isEmpty()) {
      problems.add("redis url is required when redis persistence is enabled")
    } else {
      try {
        URI(redis.url)
      } catch (e: Exception) {
        problems.add("redis url must be a redis:// or rediss:// connection string")
      }
    }
    if (redis.prefix.isEmpty()) {
      redis.prefix = DEFAULT_REDIS_PREFIX
    }
    if (redis.ttl.isZero) {
      redis.ttl = DEFAULT_PERSIST_TTL
    } else if (redis.ttl.isNegative) {
      problems.add("redis ttl must be greater than 0")
    }
  }

  return NormalizedConfig(out, warnings, problems)
}

internal class NormalizedConfig(
    val cfg: AgentConfig,
    val warnings: List<String>,
    val problems: List<String>,
) {
  val error: AgentConfigException?
    get() = if (problems.isEmpty()) null else AgentConfigException(problems.toList())
}

/**
 * config.go `normalizeEndpoint`: validates and canonicalizes the base URL the same way guard-agent
 * (Python) models.py endpoint validator does: http/https only, trailing slashes removed, and a
 * trailing /api/v1 removed with a warning because the agent appends API paths itself.
 */
internal fun normalizeEndpoint(raw: String): Triple<String, List<String>, AgentConfigException?> {
  if (raw.isEmpty()) {
    return Triple(DEFAULT_ENDPOINT, emptyList(), null)
  }
  val parsed =
      try {
        URI(raw)
      } catch (e: Exception) {
        return Triple(
            raw,
            emptyList(),
            AgentConfigException(listOf("endpoint must be a valid URL")),
        )
      }
  if (parsed.scheme.isNullOrEmpty() || parsed.host.isNullOrEmpty()) {
    return Triple(raw, emptyList(), AgentConfigException(listOf("endpoint must be a valid URL")))
  }
  val scheme = parsed.scheme.lowercase()
  if (scheme != "http" && scheme != "https") {
    return Triple(
        raw,
        emptyList(),
        AgentConfigException(listOf("endpoint scheme must be http or https")),
    )
  }
  val warnings = mutableListOf<String>()
  var trimmed = raw.trimEnd('/')
  if (trimmed.endsWith(API_VERSION_PATH_SUFFIX)) {
    trimmed = trimmed.removeSuffix(API_VERSION_PATH_SUFFIX)
    trimmed = trimmed.trimEnd('/')
    warnings.add(API_VERSION_SUFFIX_WARNING)
  }
  return Triple(trimmed, warnings, null)
}
