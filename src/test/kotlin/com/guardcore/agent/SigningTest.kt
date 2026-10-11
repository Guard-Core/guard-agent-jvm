package com.guardcore.agent

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Port of guard-agent-go `signing_test.go`: pins the exact HMAC-SHA256 scheme the ingestion server
 * verifies (payload_signature.py): "v1=" plus the lowercase hex HMAC-SHA256 digest of the body
 * under the secret.
 */
class SigningTest {
  @Test
  fun signPayloadVector() {
    val body = """{"events":[]}""".toByteArray()
    val got = signPayload(body, "test-secret")
    val want = "v1=55ad76252141f85b34debc7376f87b89c54b939e3a7663464ab3e49029495bf5"
    assertEquals(want, got)
  }

  @Test
  fun signPayloadBodySensitivity() {
    val a = signPayload("""{"events":[]}""".toByteArray(), "test-secret")
    val b = signPayload("""{"events":[1]}""".toByteArray(), "test-secret")
    assertNotEquals(a, b, "different bodies must produce different signatures")
  }

  @Test
  fun verifyPayloadSignatureRejectsMismatches() {
    val body = """{"events":[]}""".toByteArray()
    val sig = signPayload(body, "test-secret")
    assertTrue(verifyPayloadSignature(body, sig, "test-secret"), "valid signature must verify")
    assertFalse(
        verifyPayloadSignature("""{"events":[1]}""".toByteArray(), sig, "test-secret"),
        "signature over a different body must fail",
    )
    assertFalse(
        verifyPayloadSignature(body, "v1=deadbeef", "test-secret"),
        "wrong digest must fail",
    )
    assertFalse(
        verifyPayloadSignature(body, "", "test-secret") || verifyPayloadSignature(body, sig, ""),
        "empty signature or secret must fail",
    )
    assertFalse(
        verifyPayloadSignature(body, "v2=" + sig.substring(3), "test-secret"),
        "wrong version prefix must fail",
    )
  }
}
