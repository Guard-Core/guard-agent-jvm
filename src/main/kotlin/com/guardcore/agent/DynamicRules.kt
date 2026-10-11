package com.guardcore.agent

import java.net.URI
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Instant

/**
 * Port of guard-agent-go `dynamic_rules.go`: the full SaaS rule surface the engine consumes,
 * mirroring guard_agent.models.DynamicRules field for field with snake_case wire names. Decoding
 * applies the Python defaults for absent fields (the UnmarshalJSON default-then-overlay flow).
 */

// DynamicRules defaults, mirroring guard_agent.models.DynamicRules field
// defaults. They are applied by the decoder before overlaying the wire
// payload so a sparse server response decodes exactly like the pydantic
// model would.
internal const val DEFAULT_RULE_ID: String = "default-rule"
internal const val DEFAULT_RULE_VERSION: Int = 1
internal const val DEFAULT_RULE_TTL_SECONDS: Int = 300
internal const val DEFAULT_IP_BAN_DURATION: Int = 3600

public class DynamicRules {
  public var ruleId: String = DEFAULT_RULE_ID
  public var version: Int = DEFAULT_RULE_VERSION
  public var timestamp: Instant = Instant.now()
  public var expiresAt: Instant? = null
  public var ttl: Int = DEFAULT_RULE_TTL_SECONDS

  public var ipBlacklist: List<String> = emptyList()
  public var ipWhitelist: List<String> = emptyList()
  public var ipBanDuration: Int = DEFAULT_IP_BAN_DURATION

  public var blockedCountries: List<String> = emptyList()
  public var whitelistCountries: List<String> = emptyList()

  public var globalRateLimit: Int? = null
  public var globalRateWindow: Int? = null
  public var endpointRateLimits: MutableMap<String, List<Int>> = linkedMapOf()

  public var blockedCloudProviders: List<String> = emptyList()

  public var blockedUserAgents: List<String> = emptyList()

  public var suspiciousPatterns: List<String> = emptyList()

  public var enablePenetrationDetection: Boolean? = null
  public var enableIpBanning: Boolean? = null
  public var enableRateLimiting: Boolean? = null
  public var autoBanThreshold: Int? = null
  public var autoBanDuration: Int? = null
  public var enableRateLimitAutoBan: Boolean? = null

  public var emergencyMode: Boolean = false
  public var emergencyWhitelist: List<String> = emptyList()
  public var emergencyWhitelistOnly: Boolean = false
  public var message: String? = null

  /** dynamic_rules.go `DefaultDynamicRules`: the pydantic-default value with a fresh timestamp. */
  public companion object {
    public fun defaults(): DynamicRules = DynamicRules()

    /**
     * The UnmarshalJSON analog: apply the Python defaults first and overlay the wire payload, so a
     * sparse response decodes exactly like DynamicRules(**response_data) does in the Python agent.
     */
    public fun fromJson(bytes: ByteArray): DynamicRules {
      val rules = defaults()
      val wire =
          try {
            parseJson(bytes, useNumber = false)
          } catch (e: Exception) {
            throw GoJsonException(e.message ?: "invalid dynamic rules")
          }
      val map =
          wire as? Map<String, Any?> ?: throw GoJsonException("cannot unmarshal dynamic rules")

      fun strings(key: String): List<String>? = (map[key] as? List<*>)?.map { it?.toString() ?: "" }
      fun intAt(key: String): Int? =
          when (val v = map[key]) {
            null -> null
            is Double -> v.toInt()
            is Long -> v.toInt()
            is JsonNumber -> v.raw.toDoubleOrNull()?.toInt()
            else -> throw GoJsonException("json: cannot unmarshal $key")
          }
      fun boolAt(key: String): Boolean? =
          when (val v = map[key]) {
            null -> null
            is Boolean -> v
            else -> throw GoJsonException("json: cannot unmarshal $key")
          }

      (map["rule_id"] as? String)?.let { rules.ruleId = it }
      intAt("version")?.let { rules.version = it }
      (map["timestamp"] as? String)?.let { raw ->
        rules.timestamp =
            parseInstant(raw) ?: throw GoJsonException("json: cannot unmarshal timestamp")
      }
      (map["expires_at"] as? String)?.let { raw ->
        rules.expiresAt =
            parseInstant(raw) ?: throw GoJsonException("json: cannot unmarshal expires_at")
      }
      intAt("ttl")?.let { rules.ttl = it }
      strings("ip_blacklist")?.let { rules.ipBlacklist = it }
      strings("ip_whitelist")?.let { rules.ipWhitelist = it }
      intAt("ip_ban_duration")?.let { rules.ipBanDuration = it }
      strings("blocked_countries")?.let { rules.blockedCountries = it }
      strings("whitelist_countries")?.let { rules.whitelistCountries = it }
      intAt("global_rate_limit")?.let { rules.globalRateLimit = it }
      intAt("global_rate_window")?.let { rules.globalRateWindow = it }
      (map["endpoint_rate_limits"] as? Map<*, *>)?.let { limits ->
        val converted = linkedMapOf<String, List<Int>>()
        for ((k, v) in limits) {
          val pair = (v as? List<*>)?.map { (it as? Double)?.toInt() ?: 0 } ?: emptyList()
          converted[k?.toString() ?: ""] = pair
        }
        rules.endpointRateLimits = converted
      }
      strings("blocked_cloud_providers")?.let { rules.blockedCloudProviders = it }
      strings("blocked_user_agents")?.let { rules.blockedUserAgents = it }
      strings("suspicious_patterns")?.let { rules.suspiciousPatterns = it }
      boolAt("enable_penetration_detection")?.let { rules.enablePenetrationDetection = it }
      boolAt("enable_ip_banning")?.let { rules.enableIpBanning = it }
      boolAt("enable_rate_limiting")?.let { rules.enableRateLimiting = it }
      intAt("auto_ban_threshold")?.let { rules.autoBanThreshold = it }
      intAt("auto_ban_duration")?.let { rules.autoBanDuration = it }
      boolAt("enable_rate_limit_auto_ban")?.let { rules.enableRateLimitAutoBan = it }
      boolAt("emergency_mode")?.let { rules.emergencyMode = it }
      strings("emergency_whitelist")?.let { rules.emergencyWhitelist = it }
      boolAt("emergency_whitelist_only")?.let { rules.emergencyWhitelistOnly = it }
      (map["message"] as? String)?.let { rules.message = it }
      return rules
    }
  }
}

internal fun writeDynamicRulesJson(
    sb: StringBuilder,
    r: DynamicRules,
) {
  // Re-serialization emits lists, never null, mirroring pydantic's
  // default_factory=list fields.
  sb.append("{\"rule_id\":")
  appendGoString(sb, r.ruleId)
  sb.append(",\"version\":").append(r.version.toString())
  sb.append(",\"timestamp\":")
  appendGoString(sb, rfc3339Nano(r.timestamp))
  sb.append(",\"expires_at\":")
  r.expiresAt?.let { appendGoString(sb, rfc3339Nano(it)) } ?: sb.append("null")
  sb.append(",\"ttl\":").append(r.ttl.toString())
  fun listField(name: String, value: List<String>) {
    sb.append(",\"").append(name).append("\":[")
    value.forEachIndexed { i, s ->
      if (i > 0) sb.append(',')
      appendGoString(sb, s)
    }
    sb.append(']')
  }
  fun nullableInt(name: String, value: Int?) {
    sb.append(",\"").append(name).append("\":")
    sb.append(value?.toString() ?: "null")
  }
  fun nullableBool(name: String, value: Boolean?) {
    sb.append(",\"").append(name).append("\":")
    sb.append(
        when (value) {
          null -> "null"
          true -> "true"
          false -> "false"
        },
    )
  }
  listField("ip_blacklist", r.ipBlacklist)
  listField("ip_whitelist", r.ipWhitelist)
  sb.append(",\"ip_ban_duration\":").append(r.ipBanDuration.toString())
  listField("blocked_countries", r.blockedCountries)
  listField("whitelist_countries", r.whitelistCountries)
  nullableInt("global_rate_limit", r.globalRateLimit)
  nullableInt("global_rate_window", r.globalRateWindow)
  sb.append(",\"endpoint_rate_limits\":{")
  val sortedLimits = r.endpointRateLimits.entries.sortedBy { it.key }
  sortedLimits.forEachIndexed { i, (endpoint, limits) ->
    if (i > 0) sb.append(',')
    appendGoString(sb, endpoint)
    sb.append(":[")
    limits.forEachIndexed { j, v ->
      if (j > 0) sb.append(',')
      sb.append(v.toString())
    }
    sb.append(']')
  }
  sb.append('}')
  listField("blocked_cloud_providers", r.blockedCloudProviders)
  listField("blocked_user_agents", r.blockedUserAgents)
  listField("suspicious_patterns", r.suspiciousPatterns)
  nullableBool("enable_penetration_detection", r.enablePenetrationDetection)
  nullableBool("enable_ip_banning", r.enableIpBanning)
  nullableBool("enable_rate_limiting", r.enableRateLimiting)
  nullableInt("auto_ban_threshold", r.autoBanThreshold)
  nullableInt("auto_ban_duration", r.autoBanDuration)
  nullableBool("enable_rate_limit_auto_ban", r.enableRateLimitAutoBan)
  sb.append(",\"emergency_mode\":").append(if (r.emergencyMode) "true" else "false")
  listField("emergency_whitelist", r.emergencyWhitelist)
  sb.append(",\"emergency_whitelist_only\":")
      .append(if (r.emergencyWhitelistOnly) "true" else "false")
  sb.append(",\"message\":")
  r.message?.let { appendGoString(sb, it) } ?: sb.append("null")
  sb.append('}')
}

/**
 * dynamic_rules.go `fetchDynamicRules`: GETs the rules document with the same retry machinery as
 * batch sends: local rate limiter admission, circuit breaker, capped Retry-After on 429,
 * exponential backoff on every other failure. A null rules value with a null error never happens;
 * on give-up the error is returned and the caller falls back to its cache.
 */
internal fun Transport.fetchDynamicRules(ctx: AgentContext): Pair<DynamicRules?, Throwable?> {
  var attempt = 0
  while (true) {
    val (allowed, gateErr) = limiterGate(ctx, attempt, "dynamic rules fetch")
    if (!allowed) {
      if (gateErr != null) {
        return null to gateErr
      }
      continue
    }
    try {
      breaker.admit()
    } catch (err: GuardAgentException) {
      return null to err
    }
    // A pre-canceled context fails the fetch like Go's client.Do(ctx).
    if (ctx.isDone()) {
      requestsFailed.incrementAndGet()
      return null to ctx.err()
    }
    val request: HttpRequest
    try {
      val builder =
          HttpRequest.newBuilder()
              .uri(URI.create(cfg.endpoint + RULES_PATH))
              .timeout(cfg.timeout)
              .header("User-Agent", userAgent())
              .header("X-API-Key", cfg.apiKey)
              .header("X-Agent-Install-Id", installId)
      if (cfg.projectId.isNotEmpty()) {
        builder.header("X-Project-Id", cfg.projectId)
      }
      builder.GET()
      request = builder.build()
    } catch (err: Exception) {
      return null to err
    }
    val response: HttpResponse<ByteArray>
    try {
      response = client.execute(request, ByteArray(0), ctx)
    } catch (err: ContextDone) {
      breaker.failure()
      requestsFailed.incrementAndGet()
      return null to err
    } catch (err: java.io.IOException) {
      breaker.failure()
      requestsFailed.incrementAndGet()
      if (ctx.isDone()) {
        return null to ctx.err()
      }
      if (
          attempt < cfg.retryAttempts && sleepContext(ctx, retryBackoff(attempt, cfg.backoffFactor))
      ) {
        attempt++
        continue
      }
      return null to err
    } catch (panic: Throwable) {
      throw panic
    }
    val body = response.body()
    when {
      response.statusCode() == 200 -> {
        breaker.success()
        requestsSent.incrementAndGet()
        val rules =
            try {
              DynamicRules.fromJson(body)
            } catch (err: Exception) {
              requestsFailed.incrementAndGet()
              return null to
                  GuardAgentException(
                      "guardagent: malformed dynamic rules response: ${err.message}",
                      ErrorKind.INTERNAL,
                  )
            }
        return rules to null
      }
      response.statusCode() == 429 -> {
        breaker.failure()
        requestsFailed.incrementAndGet()
        val delay = parseRetryAfter(response.headers().firstValue("Retry-After").orElse(""))
        if (attempt < cfg.retryAttempts && sleepContext(ctx, delay)) {
          attempt++
          continue
        }
        return null to RateLimitedError(delay)
      }
      else -> {
        breaker.failure()
        requestsFailed.incrementAndGet()
        if (
            attempt < cfg.retryAttempts &&
                sleepContext(ctx, retryBackoff(attempt, cfg.backoffFactor))
        ) {
          attempt++
          continue
        }
        return null to
            GuardAgentException(
                "guardagent: dynamic rules request failed with status " +
                    response.statusCode() +
                    ": " +
                    truncate(body.toString(Charsets.UTF_8), 200),
                ErrorKind.INTERNAL,
            )
      }
    }
  }
}
