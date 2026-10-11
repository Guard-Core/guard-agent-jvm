package com.guardcore.agent

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream

/**
 * Port of guard-agent-go `mock_test.go`: mirrors the Guard Core App ingestion contract for tests -
 * gzip request bodies are decompressed, the HMAC signature is verified over the UNCOMPRESSED body
 * (post-decompression, like telemetry_router.py), 413 fires when the decompressed body exceeds
 * maxBody, and 200 can carry a partial failure with success:false.
 */
class CapturedCall {
  var path: String = ""
  var body: ByteArray = ByteArray(0) // decompressed
  var headers: Map<String, String> = emptyMap()
  var compressed: Boolean = false
  var batchId: String = ""
  var events: List<SecurityEvent> = emptyList()
  var metrics: List<SecurityMetric> = emptyList()
  var status: AgentStatusPayload? = null
  var response: Int = 0

  fun header(name: String): String = headers[name.lowercase()] ?: ""
}

class MockIngest : AutoCloseable {
  private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
  private val stateLock = Any()
  private val calls = mutableListOf<CapturedCall>()

  private var maxBody: Int = 262144
  private var force429N: Int = 0
  private var retryAfter: String = "1"
  private var failNextN: Int = 0
  private var force400N: Int = 0
  private var statusCodeOverride: Int = 0
  private var partialNext: Boolean = false
  private var requireSignature: Boolean = false
  private var signingSecret: String = ""
  private var rulesBody: String = ""
  private var rulesStatus: Int = 0

  val url: String = "http://127.0.0.1:" + server.address.port

  init {
    server.createContext("/") { exchange -> handle(exchange) }
    server.start()
  }

  override fun close() {
    server.stop(0)
  }

  private fun handle(exchange: HttpExchange) {
    val compressedIn = exchange.requestHeaders.getFirst("Content-Encoding") == "gzip"
    val rawBody = exchange.requestBody.readBytes()
    val body =
        if (compressedIn) {
          try {
            GZIPInputStream(rawBody.inputStream()).readBytes()
          } catch (e: Exception) {
            respond(exchange, 400, ByteArray(0))
            return
          }
        } else {
          rawBody
        }
    val headers = mutableMapOf<String, String>()
    for ((name, values) in exchange.requestHeaders.entries) {
      val value = values.firstOrNull()
      if (value != null) {
        headers[name.lowercase()] = value
      }
    }
    val path = exchange.requestURI.path ?: ""
    synchronized(stateLock) {
      val call = CapturedCall()
      call.path = path
      call.body = body
      call.headers = headers
      call.compressed = compressedIn
      when (path) {
        ENCRYPTED_PATH -> {
          val parsed =
              try {
                parseJson(body, useNumber = false) as? Map<*, *>
              } catch (e: Exception) {
                null
              }
          if (parsed == null) {
            respond(exchange, 400, ByteArray(0))
            return
          }
          call.batchId = parsed["batch_id"]?.toString() ?: ""
        }
        EVENTS_PATH,
        METRICS_PATH -> {
          val parsed =
              try {
                parseJson(body, useNumber = false) as? Map<*, *>
              } catch (e: Exception) {
                null
              }
          if (parsed == null) {
            respond(exchange, 400, ByteArray(0))
            return
          }
          call.batchId = parsed["batch_id"]?.toString() ?: ""
          call.events =
              (parsed["events"] as? List<*>)?.mapNotNull {
                (it as? Map<*, *>)?.let { m -> securityEventFromMapAny(m) }
              } ?: emptyList()
          call.metrics =
              (parsed["metrics"] as? List<*>)?.mapNotNull {
                (it as? Map<*, *>)?.let { m -> securityMetricFromMapAny(m) }
              } ?: emptyList()
        }
        STATUS_PATH -> {
          val parsed =
              try {
                parseJson(body, useNumber = false) as? Map<*, *>
              } catch (e: Exception) {
                null
              }
          if (parsed == null) {
            respond(exchange, 400, ByteArray(0))
            return
          }
          call.status = agentStatusFromMapAny(parsed)
        }
        RULES_PATH -> {
          call.response = if (rulesStatus != 0) rulesStatus else 200
          calls.add(call)
          respond(exchange, call.response, rulesBody.toByteArray())
          return
        }
        else -> {
          respond(exchange, 404, ByteArray(0))
          return
        }
      }
      if (
          requireSignature &&
              !verifyPayloadSignature(
                  body,
                  headers[SIGNATURE_HEADER.lowercase()],
                  signingSecret,
              )
      ) {
        call.response = 401
        calls.add(call)
        respond(exchange, 401, ByteArray(0))
        return
      }
      val (code, retryAfterValue) = decide(body.size)
      call.response = code
      calls.add(call)
      if (code != 200) {
        respond(exchange, code, ByteArray(0), retryAfterValue)
        return
      }
      val responseBody: ByteArray
      if (partialNext) {
        partialNext = false
        responseBody = """{"success":false,"errors":["simulated partial failure"]}""".toByteArray()
      } else {
        responseBody = """{"success":true,"errors":[]}""".toByteArray()
      }
      respond(exchange, 200, responseBody, retryAfterValue)
    }
  }

  /**
   * Applies the failure knobs in contract order: size guard first, then rate limiting, then server
   * errors, then permanent rejection.
   */
  private fun decide(bodyLen: Int): Pair<Int, String> {
    if (bodyLen > maxBody) {
      return 413 to ""
    }
    if (force429N > 0) {
      force429N--
      return 429 to retryAfter
    }
    if (failNextN > 0) {
      failNextN--
      return 500 to ""
    }
    if (force400N > 0) {
      force400N--
      return 400 to ""
    }
    if (statusCodeOverride > 0) {
      return statusCodeOverride to ""
    }
    return 200 to ""
  }

  private fun respond(
      exchange: HttpExchange,
      code: Int,
      body: ByteArray,
      retryAfter: String = "",
  ) {
    if (retryAfter.isNotEmpty()) {
      exchange.responseHeaders.add("Retry-After", retryAfter)
    }
    exchange.sendResponseHeaders(code, if (body.isEmpty()) -1 else body.size.toLong())
    if (body.isNotEmpty()) {
      exchange.responseBody.write(body)
    }
    exchange.close()
  }

  // ------------------------------------------------------------- knobs --

  fun callsTo(path: String): List<CapturedCall> =
      synchronized(stateLock) { calls.filter { it.path == path } }

  fun callCount(): Int = synchronized(stateLock) { calls.size }

  fun allCalls(): List<CapturedCall> = synchronized(stateLock) { calls.toList() }

  fun setMaxBody(n: Int) = synchronized(stateLock) { maxBody = n }

  fun failNext(n: Int) = synchronized(stateLock) { failNextN = n }

  fun rateLimitNext(
      n: Int,
      retryAfter: String,
  ) =
      synchronized(stateLock) {
        force429N = n
        this.retryAfter = retryAfter
      }

  fun reject400Next(n: Int) = synchronized(stateLock) { force400N = n }

  fun respondPartialOnce() = synchronized(stateLock) { partialNext = true }

  fun requireSignatures(secret: String) =
      synchronized(stateLock) {
        requireSignature = true
        signingSecret = secret
      }

  fun serveRules(
      status: Int,
      body: String,
  ) =
      synchronized(stateLock) {
        rulesStatus = status
        rulesBody = body
      }

  fun statusCodeOverrideForTest(code: Int) = synchronized(stateLock) { statusCodeOverride = code }

  fun clearKnobs() =
      synchronized(stateLock) {
        failNextN = 0
        force429N = 0
        force400N = 0
        statusCodeOverride = 0
        partialNext = false
      }
}

/** Gzip helper for tests that need to craft compressed wire bodies. */
internal fun gzipBytes(raw: ByteArray): ByteArray {
  val buf = ByteArrayOutputStream()
  GZIPOutputStream(buf).use { it.write(raw) }
  return buf.toByteArray()
}

/** Generic-map readers for the mock (type-loose, like encoding/json). */
internal fun securityEventFromMapAny(map: Map<*, *>): SecurityEvent {
  val converted = LinkedHashMap<String, Any?>()
  for ((k, v) in map) {
    converted[k.toString()] = v
  }
  return securityEventFromMap(converted)
}

internal fun securityMetricFromMapAny(map: Map<*, *>): SecurityMetric {
  val converted = LinkedHashMap<String, Any?>()
  for ((k, v) in map) {
    converted[k.toString()] = v
  }
  return securityMetricFromMap(converted)
}

internal fun agentStatusFromMapAny(map: Map<*, *>): AgentStatusPayload {
  val st = AgentStatusPayload()
  (map["timestamp"] as? String)?.let { raw -> st.timestamp = parseInstant(raw) }
  (map["status"] as? String)?.let { st.status = it }
  (map["uptime"])?.let { v -> st.uptime = v as? Double ?: ((v as? Long)?.toDouble() ?: 0.0) }
  (map["events_sent"])?.let { v ->
    st.eventsSent = (v as? Long) ?: ((v as? Double)?.toLong() ?: 0L)
  }
  (map["events_failed"])?.let { v ->
    st.eventsFailed = (v as? Long) ?: ((v as? Double)?.toLong() ?: 0L)
  }
  (map["buffer_size"])?.let { v ->
    st.bufferSize = (v as? Long)?.toInt() ?: ((v as? Double)?.toInt() ?: 0)
  }
  (map["last_flush"] as? String)?.let { raw -> st.lastFlush = parseInstant(raw) }
  (map["errors"] as? List<*>)?.let { st.errors = it.map { e -> e?.toString() ?: "" } }
  return st
}
