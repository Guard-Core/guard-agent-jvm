package com.guardcore.agent

import java.nio.file.Path
import javax.crypto.Cipher
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `encryption_test.go`: the crypto vector proof against the Python-generated
 * Go test vectors (byte-compat evidence), the canonical JSON byte pins, key validation, tamper/AAD
 * rejection, and the encrypted-ingest end-to-end path.
 */
class EncryptionTest {
  /** encryption_test.go `loadVectors`. */
  private fun loadVectors(): List<EncVector> {
    val raw =
        EncryptionTest::class
            .java
            .classLoader
            .getResourceAsStream("testdata/encryption_vectors.json")
            ?.readBytes() ?: error("read vectors: testdata/encryption_vectors.json missing")
    val parsed = parseJson(raw, useNumber = false) as? List<*> ?: error("parse vectors: not a list")
    val vectors = parsed.map { item ->
      val map = item as? Map<*, *> ?: error("parse vectors: not an object")
      EncVector(
          map["key_b64"]?.toString() ?: "",
          map["plaintext_json"]?.toString() ?: "",
          map["ciphertext_b64"]?.toString() ?: "",
          map["tampered_ciphertext_b64"]?.toString() ?: "",
          map["aad"]?.toString() ?: "",
      )
    }
    assertEquals(4, vectors.size, "expected 4 vectors")
    return vectors
  }

  class EncVector(
      val keyB64: String,
      val plaintextJSON: String,
      val ciphertextB64: String,
      val tamperedCiphertextB64: String,
      val aad: String,
  )

  @Test
  fun payloadEncryptorDecryptsPythonVectors() {
    for ((i, v) in loadVectors().withIndex()) {
      val encryptor = PayloadEncryptor.create(v.keyB64)
      val decrypted = encryptor.decrypt(v.ciphertextB64, v.aad)
      // The canonical re-rendering must equal the pinned plaintext
      // bytes byte for byte (the Go test marshals both sides).
      assertEquals(v.plaintextJSON, canonicalJSON(decrypted), "vector $i")
    }
  }

  @Test
  fun payloadEncryptorCanonicalJSONBytePins() {
    // The serializer must reproduce the Python plaintext bytes exactly.
    for ((i, v) in loadVectors().withIndex()) {
      val data =
          parseJson(v.plaintextJSON, useNumber = true) as? Map<String, Any?>
              ?: error("vector $i: not an object")
      assertEquals(v.plaintextJSON, canonicalJSON(data), "vector $i")
    }
    // ensure_ascii escaping with surrogate pairs (Go: "h\u00e9llo ...").
    val unicode = "h\u00e9llo w\u00f6rld \u4f60\u597d"
    assertEquals(
        "{\"unicode\":\"h\\u00e9llo w\\u00f6rld \\u4f60\\u597d\"}",
        canonicalJSON(linkedMapOf("unicode" to unicode)),
    )
    val emoji = "\uD83D\uDE00"
    assertEquals(
        "{\"emoji\":\"\\ud83d\\ude00\"}",
        canonicalJSON(linkedMapOf("emoji" to emoji)),
    )
  }

  @Test
  fun payloadEncryptorKeyValidation() {
    assertFailsWith<EncryptionError> { PayloadEncryptor.create("") }
    val err = assertFailsWith<EncryptionError> { PayloadEncryptor.create("AAAA") }
    assertTrue(err.message!!.contains("key size"), "undersized key message: ${err.message}")
    assertNull(createEncryptor(""), "CreateEncryptor with empty key must be null")
  }

  @Test
  fun payloadEncryptorTamperAndAAD() {
    val v = loadVectors()[0]
    val encryptor = PayloadEncryptor.create(v.keyB64)
    assertFailsWith<EncryptionError> { encryptor.decrypt(v.tamperedCiphertextB64, "") }
    val aadVector = loadVectors()[3]
    assertFailsWith<EncryptionError> { encryptor.decrypt(aadVector.ciphertextB64, "wrong") }
    // The guard-agent 3.2.3 tamper fidelity improvement: tamper by XOR-flipping the
    // last encrypted byte (inside the GCM tag) instead of appending, so the
    // rejection always exercises authentication and can never pass on a length
    // check (ports test_encryption.py test_decrypt_tampered_payload).
    val encrypted = encryptor.encrypt(linkedMapOf<String, Any?>("test" to "value"), "")
    val encryptedBytes = decodeUrlsafeBase64(encrypted)
    encryptedBytes[encryptedBytes.size - 1] =
        (encryptedBytes[encryptedBytes.size - 1].toInt() xor 0xFF).toByte()
    assertFailsWith<EncryptionError> {
      encryptor.decrypt(encodeUrlsafeBase64(encryptedBytes), "")
    }
  }

  @Test
  fun payloadEncryptorRoundTripAndPadding() {
    val v = loadVectors()[0]
    val encryptor = PayloadEncryptor.create(v.keyB64)
    val data =
        linkedMapOf<String, Any?>(
            "events" to
                listOf<Any?>(
                    linkedMapOf<String, Any?>(
                        "event_type" to "rate_limit",
                        "ip_address" to "1.2.3.4",
                    ),
                ),
            "metrics" to listOf<Any?>(),
            "zeta" to 1,
            "unicode" to "hello",
        )
    val encrypted = encryptor.encrypt(data, "")
    assertTrue(
        encrypted.length % 4 == 0 && !encrypted.dropLast(2).any { it == '+' || it == '/' },
        "output is not padded urlsafe base64: $encrypted",
    )
    val decrypted = encryptor.decrypt(encrypted, "")
    // Compare canonical renderings (the Go test marshals both sides).
    assertEquals(canonicalJSON(roundTripView(data)), canonicalJSON(decrypted))
    assertTrue(encryptor.verifyKey(), "VerifyKey failed for a valid key")
  }

  /**
   * Re-decodes the model through the number-preserving path, like the Go marshal/decode compare.
   */
  private fun roundTripView(data: Map<String, Any?>): Map<String, Any?> =
      parseJson(goJson(data).toString(Charsets.UTF_8), useNumber = true) as Map<String, Any?>

  @Test
  fun agentRejectsInvalidEncryptionKey() {
    val cfg = defaultConfig()
    cfg.apiKey = "test-api-key-123"
    cfg.projectEncryptionKey = "not-a-valid-key"
    val err = assertFailsWith<EncryptionConfigError> { GuardAgent.create(cfg) }
    assertTrue(
        err.message!!.startsWith(
            "Encryption round-trip failed at startup; refusing plaintext fallback",
        ),
        err.message,
    )
  }

  @Test
  fun agentEncryptedIngestEndToEnd() {
    val v = loadVectors()[0]
    val tmp: Path = tempDirFor("enc-e2e")
    val mock = MockIngest()
    val agent = newTestAgent(tmp, mock) { c -> c.projectEncryptionKey = v.keyB64 }
    try {
      agent.sendEvent(SecurityEvent(null, "penetration_attempt", ipAddress = "203.0.113.7"))
      assertEquals(null, agent.flush())
      val calls = mock.callsTo(ENCRYPTED_PATH)
      assertEquals(1, calls.size, "expected 1 encrypted call")
      assertEquals(0, mock.callsTo(EVENTS_PATH).size, "plaintext events endpoint was used")
      // Open the envelope under the configured key.
      val encryptor = PayloadEncryptor.create(v.keyB64)
      val envelope =
          parseJson(calls[0].body, useNumber = false) as? Map<*, *> ?: error("unmarshal envelope")
      val batchId = envelope["batch_id"]?.toString() ?: ""
      val agentVersion = envelope["agent_version"]?.toString() ?: ""
      assertTrue(batchId.isNotEmpty() && agentVersion.isNotEmpty(), "envelope missing clear fields")
      val inner = encryptor.decrypt(envelope["encrypted_payload"].toString(), "")
      val events = inner["events"] as? List<*>
      assertEquals(1, events?.size, "inner payload events wrong")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  @Test
  fun agentEncryptedStatusStaysPlaintext() {
    val v = loadVectors()[0]
    val tmp: Path = tempDirFor("enc-status")
    val mock = MockIngest()
    val agent = newTestAgent(tmp, mock) { c -> c.projectEncryptionKey = v.keyB64 }
    try {
      val payload = AgentStatusPayload()
      payload.timestamp = java.time.Instant.now()
      payload.status = "healthy"
      val (outcome, err) = agent.tr.sendStatus(AgentContext.NONE, payload)
      assertEquals(null, err, "sendStatus error")
      assertEquals(SendOutcome.ACCEPTED, outcome, "status outcome")
      assertEquals(1, mock.callsTo(STATUS_PATH).size, "expected 1 status call")
      assertEquals(0, mock.callsTo(ENCRYPTED_PATH).size, "status report was encrypted")
    } finally {
      agent.stop()
      mock.close()
    }
  }

  /**
   * Port of coverage_more_test.go `TestVerifyKeyFailsWhenDecryptFails`: the Go fakeAEAD makes Open
   * always fail; the JVM seam swaps the cipher factory so the decrypt leg of the round trip
   * explodes.
   */
  @Test
  fun verifyKeyFailsWhenDecryptFails() {
    val v = loadVectors()[0]
    val encryptor = PayloadEncryptor.create(v.keyB64)
    var calls = 0
    encryptor.cipherFactory = {
      calls++
      if (calls >= 2) {
        throw IllegalStateException("open exploded")
      }
      Cipher.getInstance("AES/GCM/NoPadding")
    }
    assertFalse(encryptor.verifyKey(), "VerifyKey must fail when the round-trip open fails")
  }
}
