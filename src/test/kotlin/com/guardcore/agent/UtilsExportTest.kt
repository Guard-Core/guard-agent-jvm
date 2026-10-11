package com.guardcore.agent

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Port of guard-agent-go `utils_export_test.go`. */
class UtilsExportTest {
  @Test
  fun generateBatchIDShape() {
    val id = generateBatchID()
    assertTrue(id.isNotEmpty(), "the batch id must not be empty")
    val dash = id.indexOf('-')
    assertTrue(
        dash > 0 && dash != id.length - 1,
        "the batch id must be {unix_millis}-{hex}, got $id",
    )
    val hexPart = id.substring(dash + 1)
    assertEquals(8, hexPart.length, "the random suffix must be 8 hex chars")
    assertNotEquals(id, generateBatchID(), "consecutive ids must differ")
  }

  @Test
  fun summarizeResponseBody() {
    assertEquals(
        "one two three four",
        summarizeResponseBody("one  two\n\nthree\t\tfour", 100),
        "whitespace must collapse to single spaces",
    )
    val long = "a".repeat(500)
    val got = summarizeResponseBody(long, 100)
    assertTrue(
        got.startsWith("a".repeat(100) + "... [truncated, 500 chars total]"),
        "a long body must cap with the original length noted, got $got",
    )
    assertEquals(
        "short",
        summarizeResponseBody("short", 0),
        "a non-positive cap must return the collapsed body",
    )
  }

  @Test
  fun safeJSONSerialize() {
    val encoded = safeJSONSerialize(linkedMapOf("a" to 1))
    assertEquals("{\"a\":1}", encoded, "objects must serialize compactly")
    // An unserializable value raises SerializationError carrying the
    // marshal problem (the Go test marshals a channel).
    val err = assertFailsWith<SerializationError> { safeJSONSerialize(Thread()) }
    assertTrue(err.message!!.isNotEmpty(), "the error must carry the marshal problem")
  }

  @Test
  fun safeJSONDeserialize() {
    val obj = safeJSONDeserialize("{\"a\": 1}")
    assertEquals(1.0, obj?.get("a"), "objects must deserialize")
    assertEquals(null, safeJSONDeserialize("[1,2]"), "a non-object payload must return nil")
    assertEquals(null, safeJSONDeserialize("{not json"), "a parse failure must return nil")
  }

  @Test
  fun validateConfigReportsProblems() {
    val problems =
        validateConfig(
            AgentConfig().apply {
              apiKey = "short"
              endpoint = "ftp://not-http"
            },
        )
    assertTrue(problems.isNotEmpty(), "an invalid config must report problems")
    val joined = problems.joinToString("; ")
    assertTrue(
        joined.contains("api key") && joined.contains("endpoint"),
        "the problems must name the fields, got \"$joined\"",
    )

    val sound = defaultConfig()
    sound.apiKey = "a-sufficiently-long-api-key"
    sound.endpoint = "https://ingest.example.com"
    assertEquals(emptyList(), validateConfig(sound), "a sound config must report no problems")
  }

  @Test
  fun generateBatchIDTimestampAffinity() {
    val before = System.currentTimeMillis()
    val id = generateBatchID()
    val after = System.currentTimeMillis()
    val prefix = id.substring(0, id.indexOf('-'))
    val millis = prefix.toLongOrNull() ?: error("the timestamp prefix must parse, got $id")
    assertTrue(
        millis >= before - 1000 && millis <= after + 1000,
        "the timestamp must be current, got $millis in [$before, $after]",
    )
  }

  // Port of parity_test.go LOW units that live in utils.go.

  @Test
  fun truncatePayload() {
    assertEquals("short", truncatePayload("short", 10))
    val got = truncatePayload("0123456789abcdef", 10)
    assertEquals("0123456789...[TRUNCATED]", got)
    assertEquals(10 + "...[TRUNCATED]".length, got.length)
  }

  @Test
  fun hashIPMatchesPythonVector() {
    // hashlib.sha256(b"203.0.113.7salty").hexdigest()[:16] on the Python baseline.
    assertEquals("baea654513019302", hashIP("203.0.113.7", "salty"))
    assertEquals(16, hashIP("203.0.113.7", "").length)
  }
}
