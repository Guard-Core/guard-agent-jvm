package com.guardcore.agent

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * The Go encoding/json analog for the agent's wire surfaces. The reference agent emits and consumes
 * encoding/json bytes: struct field order, map key sorting, HTML string escaping, floatEncoder
 * formatting, RFC3339Nano timestamps, and (for the encryption canonicalization) a UseNumber decode
 * that preserves number text. java.net.http consumers of the ingestion API only see these bytes
 * through HMAC signatures and the API's parser, so the writer is byte-faithful to encoding/json.
 */
internal class GoJsonException(message: String) : RuntimeException(message)

/**
 * encoding/json `json.Number`: the raw number text, preserved verbatim through canonicalization
 * exactly like the transport's UseNumber decode (transport.go `decodeGenericJSON`).
 */
internal class JsonNumber(
    public val raw: String,
) {
  override fun toString(): String = raw

  override fun equals(other: Any?): Boolean = other is JsonNumber && other.raw == raw

  override fun hashCode(): Int = raw.hashCode()
}

// ------------------------------------------------------------------ floats --

internal object GoFloat {
  /**
   * Shortest round-trip digits for a finite double: returns the digit string (no trailing zeros)
   * and the decimal point position dp (the number of digits before the decimal point in fixed
   * notation; dp <= 0 means leading zeros after "0."). Computed with an %e precision ladder, the
   * standard pre-JDK-19 shortest-round-trip technique (the JVM baseline is 17, whose
   * Double.toString is not always shortest).
   */
  fun shortest(v: Double): Pair<String, Int> {
    var sign = ""
    var x = v
    if (x < 0 || (x == 0.0 && 1.0 / x < 0)) {
      sign = "-"
      x = -x
    }
    if (x == 0.0) {
      return sign + "0" to 1
    }
    var p = 1
    while (p <= 17) {
      val formatted = String.format(Locale.ROOT, "%." + p + "e", x)
      if (java.lang.Double.parseDouble(formatted) == x) {
        val eIndex = formatted.indexOf('e')
        val mantissa = formatted.substring(0, eIndex)
        val exp = formatted.substring(eIndex + 1).toInt()
        val digits = mantissa.replace(".", "").trimEnd('0').ifEmpty { "0" }
        return sign + digits to exp + 1
      }
      p++
    }
    // Unreachable for finite doubles: 17 significant digits always round-trip.
    val fallback = java.lang.Double.toString(x)
    return sign + fallback to fallback.length
  }

  /** Fixed (non-exponent) rendering of digits/dp, Go strconv 'f' style. */
  fun fixed(digits: String, dp: Int): String {
    val sign = if (digits.startsWith("-")) "-" else ""
    val d = if (digits.startsWith("-")) digits.substring(1) else digits
    return when {
      dp <= 0 -> sign + "0." + "0".repeat(-dp) + d
      dp >= d.length -> sign + d + "0".repeat(dp - d.length)
      else -> sign + d.substring(0, dp) + "." + d.substring(dp)
    }
  }

  /**
   * encoding/json floatEncoder: 'f' shortest unless abs < 1e-6 or abs >= 1e21, then 'e' shortest
   * with the json exponent cleanup (1e-07 renders as 1e-7).
   */
  fun goJson(v: Double): String {
    if (v.isNaN() || v.isInfinite()) {
      throw GoJsonException("json: unsupported value: $v")
    }
    val sign = if (v < 0 || (v == 0.0 && 1.0 / v < 0)) "-" else ""
    val abs = Math.abs(v)
    val (digits0, dp) = shortest(abs)
    val digits = if (sign == "-") digits0.removePrefix("-") else digits0
    return if (abs != 0.0 && (abs < 1.0e-6 || abs >= 1.0e21)) {
      // Exponent form: mantissa with a single leading digit, 2-digit
      // minimum exponent, then the encoding/json cleanup that strips the
      // leading zero of a negative two-digit exponent.
      var expForm = exponentForm(digits, dp - 1)
      if (expForm.contains("e-0")) {
        expForm = expForm.replace("e-0", "e-")
      }
      expForm
    } else {
      fixed(digits, dp)
    }
  }

  /**
   * encryption.go `writeCanonicalFloat`: Python-repr style. Whole values within +-1e15 render with
   * a forced ".0"; everything else renders like strconv 'g' shortest, which switches to exponent
   * form when the decimal exponent is < -4 or >= 6.
   */
  fun canonical(v: Double): String {
    if (v.isNaN() || v.isInfinite()) {
      throw GoJsonException("json: unsupported value: $v")
    }
    val (signedDigits, dp) = shortest(v)
    val negative = signedDigits.startsWith("-")
    val digits = if (negative) signedDigits.substring(1) else signedDigits
    val whole = v == v.toLong().toDouble()
    if (whole && v >= -1.0e15 && v <= 1.0e15) {
      var s = fixed(digits, dp)
      if (negative) {
        s = "-$s"
      }
      if (!s.contains('.')) {
        s += ".0"
      }
      return s
    }
    val exp = dp - 1
    val body =
        if (exp < -4 || exp >= 6) {
          exponentForm(digits, exp)
        } else {
          fixed(digits, dp)
        }
    return if (negative) "-$body" else body
  }

  /** strconv 'e' shortest: d[.ddd]e<sign><at least 2 digits>. */
  private fun exponentForm(digits: String, exp: Int): String {
    val mantissa =
        if (digits.length == 1) {
          digits
        } else {
          digits.substring(0, 1) + "." + digits.substring(1)
        }
    val sign = if (exp < 0) "-" else "+"
    val magnitude = if (exp < 0) -exp else exp
    return mantissa + "e" + sign + "%02d".format(magnitude)
  }
}

// ------------------------------------------------------------------ strings --

/** encoding/json string escaping: HTML bytes (<, >, &), control, U+2028/9. */
internal fun appendGoString(
    sb: StringBuilder,
    s: String,
) {
  sb.append('"')
  var i = 0
  val n = s.length
  while (i < n) {
    val c = s[i]
    when {
      c == '"' -> sb.append("\\\"")
      c == '\\' -> sb.append("\\\\")
      c == '\n' -> sb.append("\\n")
      c == '\r' -> sb.append("\\r")
      c == '\t' -> sb.append("\\t")
      c < ' ' -> sb.append("\\u").append(String.format(Locale.ROOT, "%04x", c.code))
      c == '<' -> sb.append("\\u003c")
      c == '>' -> sb.append("\\u003e")
      c == '&' -> sb.append("\\u0026")
      c == '\u2028' -> sb.append("\\u2028")
      c == '\u2029' -> sb.append("\\u2029")
      c.isHighSurrogate() -> {
        if (i + 1 < n && s[i + 1].isLowSurrogate()) {
          sb.append(c)
          sb.append(s[i + 1])
          i++
        } else {
          sb.append("\\ufffd")
        }
      }
      c.isLowSurrogate() -> sb.append("\\ufffd")
      else -> sb.append(c)
    }
    i++
  }
  sb.append('"')
}

/**
 * encryption.go `writeCanonicalString`: Python ensure_ascii escaping. Short escapes for " \\ b f n
 * r t, \\uXXXX for other control and non-ASCII characters, surrogate pairs for astral planes.
 */
internal fun appendCanonicalString(
    sb: StringBuilder,
    text: String,
) {
  sb.append('"')
  var i = 0
  val n = text.length
  while (i < n) {
    val c = text[i]
    if (c.isHighSurrogate()) {
      if (i + 1 < n && text[i + 1].isLowSurrogate()) {
        sb.append("\\u").append(String.format(Locale.ROOT, "%04x", c.code))
        sb.append("\\u").append(String.format(Locale.ROOT, "%04x", text[i + 1].code))
        i += 2
        continue
      }
      sb.append("\\ufffd")
      i++
      continue
    }
    if (c.isLowSurrogate()) {
      sb.append("\\ufffd")
      i++
      continue
    }
    when (c) {
      '"' -> sb.append("\\\"")
      '\\' -> sb.append("\\\\")
      '\b' -> sb.append("\\b")
      '\u000C' -> sb.append("\\f")
      '\n' -> sb.append("\\n")
      '\r' -> sb.append("\\r")
      '\t' -> sb.append("\\t")
      else -> {
        val code = c.code
        if (code < 0x20 || code > 0x7e) {
          sb.append("\\u").append(String.format(Locale.ROOT, "%04x", code))
        } else {
          sb.append(c)
        }
      }
    }
    i++
  }
  sb.append('"')
}

// --------------------------------------------------------------- timestamps --

/** Go time.Time RFC3339Nano rendering (trailing fractional zeros removed). */
internal fun rfc3339Nano(t: Instant): String {
  val zdt = t.atZone(ZoneOffset.UTC)
  val sb = StringBuilder(zdt.format(RFC3339_BASE))
  val nanos = zdt.nano
  if (nanos != 0) {
    sb.append('.')
    sb.append("%09d".format(nanos).trimEnd('0'))
  }
  sb.append('Z')
  return sb.toString()
}

private val RFC3339_BASE: DateTimeFormatter =
    DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss", Locale.US)

// ------------------------------------------------------------------- writer --

/**
 * encoding/json Marshal for the agent's value domain: typed wire structs in declaration order, maps
 * with sorted keys, encoding/json escaping and float formatting everywhere. Unknown types fail like
 * encoding/json ("json: unsupported type").
 */
internal fun goJson(value: Any?): ByteArray {
  val sb = StringBuilder()
  writeGoValue(sb, value)
  return sb.toString().toByteArray(Charsets.UTF_8)
}

internal fun writeGoValue(
    sb: StringBuilder,
    value: Any?,
) {
  when (value) {
    null -> sb.append("null")
    is Boolean -> sb.append(if (value) "true" else "false")
    is String -> appendGoString(sb, value)
    is Int,
    is Long,
    is Short,
    is Byte -> sb.append(value.toString())
    is Double -> sb.append(GoFloat.goJson(value))
    is Float -> sb.append(GoFloat.goJson(value.toDouble()))
    is JsonNumber -> sb.append(value.raw)
    is Instant -> appendGoString(sb, rfc3339Nano(value))
    is SecurityEvent -> writeSecurityEventJson(sb, value)
    is SecurityMetric -> writeSecurityMetricJson(sb, value)
    is EventBatch -> writeEventBatchJson(sb, value)
    is AgentStatusPayload -> writeAgentStatusJson(sb, value)
    is EncryptedEnvelope -> writeEncryptedEnvelopeJson(sb, value)
    is Map<*, *> -> {
      sb.append('{')
      val keys = value.keys.map { it?.toString() ?: "null" }.sorted()
      for ((index, key) in keys.withIndex()) {
        if (index > 0) {
          sb.append(',')
        }
        appendGoString(sb, key)
        sb.append(':')
        writeGoValue(sb, value[keyOf(key, value)])
      }
      sb.append('}')
    }
    is List<*> -> {
      sb.append('[')
      for ((index, item) in value.withIndex()) {
        if (index > 0) {
          sb.append(',')
        }
        writeGoValue(sb, item)
      }
      sb.append(']')
    }
    else -> throw GoJsonException("json: unsupported type: " + value::class.java.name)
  }
}

internal fun keyOf(
    key: String,
    map: Map<*, *>,
): Any? = map.keys.firstOrNull { it?.toString() == key }

// ------------------------------------------------------------------- parser --

/**
 * encoding/json Unmarshal into interface{} (with the transport's UseNumber option): objects decode
 * to LinkedHashMap, arrays to ArrayList, numbers to Double, or to [JsonNumber] when [useNumber].
 */
internal fun parseJson(
    text: String,
    useNumber: Boolean,
): Any? {
  val parser = JsonParser(text, useNumber)
  val value = parser.parseValue()
  parser.skipWhitespace()
  if (!parser.atEnd()) {
    throw GoJsonException("invalid character after top-level value")
  }
  return value
}

internal fun parseJson(
    bytes: ByteArray,
    useNumber: Boolean,
): Any? = parseJson(bytes.toString(Charsets.UTF_8), useNumber)

private class JsonParser(
    private val text: String,
    private val useNumber: Boolean,
) {
  private var pos = 0

  fun atEnd(): Boolean = pos >= text.length

  fun skipWhitespace() {
    while (
        pos < text.length && text[pos].let { it == ' ' || it == '\t' || it == '\n' || it == '\r' }
    ) {
      pos++
    }
  }

  fun parseValue(): Any? {
    skipWhitespace()
    if (atEnd()) {
      throw GoJsonException("unexpected end of JSON input")
    }
    return when (text[pos]) {
      '{' -> parseObject()
      '[' -> parseArray()
      '"' -> parseString()
      't' -> {
        expect("true")
        true
      }
      'f' -> {
        expect("false")
        false
      }
      'n' -> {
        expect("null")
        null
      }
      else -> parseNumber()
    }
  }

  private fun expect(word: String) {
    if (!text.startsWith(word, pos)) {
      throw GoJsonException("invalid literal at $pos")
    }
    pos += word.length
  }

  private fun parseObject(): LinkedHashMap<String, Any?> {
    val result = LinkedHashMap<String, Any?>()
    pos++ // '{'
    skipWhitespace()
    if (!atEnd() && text[pos] == '}') {
      pos++
      return result
    }
    while (true) {
      skipWhitespace()
      if (atEnd() || text[pos] != '"') {
        throw GoJsonException("expected object key at $pos")
      }
      val key = parseString()
      skipWhitespace()
      if (atEnd() || text[pos] != ':') {
        throw GoJsonException("expected ':' at $pos")
      }
      pos++
      result[key] = parseValue()
      skipWhitespace()
      if (atEnd()) {
        throw GoJsonException("unexpected end of JSON input")
      }
      when (text[pos]) {
        ',' -> pos++
        '}' -> {
          pos++
          return result
        }
        else -> throw GoJsonException("expected ',' or '}' at $pos")
      }
    }
  }

  private fun parseArray(): ArrayList<Any?> {
    val result = ArrayList<Any?>()
    pos++ // '['
    skipWhitespace()
    if (!atEnd() && text[pos] == ']') {
      pos++
      return result
    }
    while (true) {
      result.add(parseValue())
      skipWhitespace()
      if (atEnd()) {
        throw GoJsonException("unexpected end of JSON input")
      }
      when (text[pos]) {
        ',' -> pos++
        ']' -> {
          pos++
          return result
        }
        else -> throw GoJsonException("expected ',' or ']' at $pos")
      }
    }
  }

  private fun parseString(): String {
    pos++ // '"'
    val sb = StringBuilder()
    while (true) {
      if (atEnd()) {
        throw GoJsonException("unexpected end of JSON input")
      }
      when (val c = text[pos]) {
        '"' -> {
          pos++
          return sb.toString()
        }
        '\\' -> {
          pos++
          if (atEnd()) {
            throw GoJsonException("unexpected end of JSON input")
          }
          when (val esc = text[pos]) {
            '"' -> sb.append('"')
            '\\' -> sb.append('\\')
            '/' -> sb.append('/')
            'b' -> sb.append('\b')
            'f' -> sb.append('\u000C')
            'n' -> sb.append('\n')
            'r' -> sb.append('\r')
            't' -> sb.append('\t')
            'u' -> {
              if (pos + 4 >= text.length) {
                throw GoJsonException("invalid \\u escape")
              }
              val hex = text.substring(pos + 1, pos + 5)
              val code = hex.toIntOrNull(16) ?: throw GoJsonException("invalid \\u escape: $hex")
              sb.append(code.toChar())
              pos += 4
            }
            else -> throw GoJsonException("invalid escape: \\$esc")
          }
          pos++
        }
        else -> {
          if (c.code < 0x20) {
            throw GoJsonException("invalid control character in string")
          }
          sb.append(c)
          pos++
        }
      }
    }
  }

  private fun parseNumber(): Any {
    val start = pos
    if (!atEnd() && (text[pos] == '-' || text[pos] == '+')) {
      pos++
    }
    while (!atEnd() && (text[pos].isDigit() || text[pos] in ".eE+-")) {
      pos++
    }
    val raw = text.substring(start, pos)
    if (raw.isEmpty()) {
      throw GoJsonException("invalid number at $start")
    }
    if (useNumber) {
      return JsonNumber(raw)
    }
    val asDouble = raw.toDoubleOrNull() ?: throw GoJsonException("invalid number: $raw")
    return asDouble
  }
}
