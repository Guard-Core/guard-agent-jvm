package com.guardcore.agent

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Port of guard-agent-go `signing.go`: the ingestion API expects payloads signed with HMAC-SHA256
 * over the uncompressed JSON body, delivered as "v1=" plus the lowercase hex digest in the
 * X-Payload-Signature header. The server verifies the signature after its gzip middleware
 * decompresses the request, so the signature MUST cover the uncompressed bytes even when the body
 * travels gzipped. This intentionally differs from the Python and TypeScript agents, which sign the
 * post-compression wire bytes and fail verification whenever gzip kicks in.
 */
public const val SIGNATURE_HEADER: String = "X-Payload-Signature"
private const val SIGNATURE_PREFIX: String = "v1="

private fun hmacSha256(
    body: ByteArray,
    secret: String,
): ByteArray {
  val mac = Mac.getInstance("HmacSHA256")
  mac.init(SecretKeySpec(secret.toByteArray(Charsets.UTF_8), "HmacSHA256"))
  return mac.doFinal(body)
}

/** signing.go `signPayload`: the "v1=" + HMAC-SHA256 hex signature of body under secret. */
public fun signPayload(
    body: ByteArray,
    secret: String,
): String {
  val digest = hmacSha256(body, secret)
  return SIGNATURE_PREFIX + digest.joinToString("") { "%02x".format(it) }
}

/**
 * signing.go `verifyPayloadSignature`: mirrors the server-side check in guard-core-api
 * payload_signature.py: strip the "v1=" prefix, recompute the HMAC-SHA256 hex digest, and compare
 * in constant time.
 */
public fun verifyPayloadSignature(
    body: ByteArray,
    signature: String?,
    secret: String,
): Boolean {
  if (signature.isNullOrEmpty() || secret.isEmpty()) {
    return false
  }
  val expected = signPayload(body, secret)
  return constantTimeEquals(
      expected.toByteArray(Charsets.UTF_8),
      signature.toByteArray(Charsets.UTF_8),
  )
}

private fun constantTimeEquals(
    a: ByteArray,
    b: ByteArray,
): Boolean {
  if (a.size != b.size) {
    return false
  }
  var result = 0
  for (i in a.indices) {
    result = result or (a[i].toInt() xor b[i].toInt())
  }
  return result == 0
}
