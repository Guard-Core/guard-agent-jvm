package com.guardcore.agent

import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Port of guard-agent-go `encryption.go`: AES-256-GCM payload encryption byte-for-byte with the
 * Python agent on the wire - canonical JSON plaintext (keys sorted recursively, compact separators,
 * Python ensure_ascii escaping), a fresh 12-byte random nonce prefixing each ciphertext, the
 * 16-byte GCM auth tag appended, and padded urlsafe base64 output.
 */

// Encryption wire constants, mirroring guard_agent/encryption.py.
internal const val ENCRYPTION_NONCE_SIZE: Int = 12
internal const val ENCRYPTION_KEY_SIZE: Int = 32
private const val GCM_TAG_BITS: Int = 128

/** encryption.go `EncryptionError`: any encryption or key-decoding failure. */
public class EncryptionError(
    message: String,
) : RuntimeException(message)

/**
 * encryption.go `EncryptionConfigError`: raised when encryption initialization fails; plaintext
 * fallback is forbidden.
 */
public class EncryptionConfigError(
    message: String,
    cause: Throwable? = null,
) : RuntimeException(message, cause)

/** encryption.go `PayloadEncryptor`: encrypts telemetry payloads with AES-256-GCM. */
public class PayloadEncryptor
private constructor(
    private val keyBytes: ByteArray,
) {
  /**
   * The cipher factory seam (the Go tests inject a fakeAEAD through the aead field); production
   * always builds a fresh AES/GCM cipher.
   */
  internal var cipherFactory: () -> Cipher = { Cipher.getInstance("AES/GCM/NoPadding") }

  private fun newCipher(): Cipher = cipherFactory()

  /**
   * encryption.go `Encrypt`: the padded urlsafe-base64 nonce||ciphertext||tag string,
   * byte-compatible with the Python agent's PayloadEncryptor.encrypt.
   */
  public fun encrypt(
      data: Map<String, Any?>,
      associatedData: String,
  ): String {
    val plaintext = canonicalJSON(data)
    val nonce = ByteArray(ENCRYPTION_NONCE_SIZE)
    try {
      cryptoRandRead(nonce)
    } catch (e: Exception) {
      throw EncryptionError("Failed to encrypt payload: $e")
    }
    val cipher = newCipher()
    cipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(keyBytes, "AES"),
        GCMParameterSpec(GCM_TAG_BITS, nonce),
    )
    if (associatedData.isNotEmpty()) {
      cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
    }
    val sealed = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    val combined = nonce + sealed
    return encodeUrlsafeBase64(combined)
  }

  /**
   * encryption.go `Decrypt`: decrypts an encrypted payload (primarily for testing; in normal
   * operation only the core backend decrypts).
   */
  public fun decrypt(
      encryptedData: String,
      associatedData: String,
  ): Map<String, Any?> {
    val combined =
        try {
          decodeUrlsafeBase64(encryptedData)
        } catch (e: Exception) {
          throw EncryptionError("Invalid or tampered payload")
        }
    if (combined.size < ENCRYPTION_NONCE_SIZE + 16) {
      throw EncryptionError("Invalid or tampered payload")
    }
    val nonce = combined.copyOfRange(0, ENCRYPTION_NONCE_SIZE)
    val ciphertext = combined.copyOfRange(ENCRYPTION_NONCE_SIZE, combined.size)
    val plaintext =
        try {
          val cipher = newCipher()
          cipher.init(
              Cipher.DECRYPT_MODE,
              SecretKeySpec(keyBytes, "AES"),
              GCMParameterSpec(GCM_TAG_BITS, nonce),
          )
          if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData.toByteArray(Charsets.UTF_8))
          }
          cipher.doFinal(ciphertext)
        } catch (e: Exception) {
          throw EncryptionError("Invalid or tampered payload")
        }
    val parsed =
        try {
          parseJson(plaintext, useNumber = true)
        } catch (e: Exception) {
          throw EncryptionError("Invalid or tampered payload")
        }
    @Suppress("UNCHECKED_CAST")
    return parsed as? Map<String, Any?> ?: throw EncryptionError("Invalid or tampered payload")
  }

  /** encryption.go `VerifyKey`: an encrypt/decrypt round trip. */
  public fun verifyKey(): Boolean {
    val testData = linkedMapOf<String, Any?>("test" to "verification")
    return try {
      val encrypted = encrypt(testData, "")
      val decrypted = decrypt(encrypted, "")
      // Compare canonical renderings, like the Go bytes.Equal over marshals.
      canonicalJSON(decrypted) == canonicalJSON(testData)
    } catch (e: Exception) {
      false
    }
  }

  public companion object {
    /**
     * encryption.go `NewPayloadEncryptor`: decodes a padded (or unpadded) urlsafe-base64 256-bit
     * project key.
     */
    public fun create(projectKey: String): PayloadEncryptor {
      if (projectKey.isEmpty()) {
        throw EncryptionError("Project key cannot be empty")
      }
      val decoded =
          try {
            decodeUrlsafeBase64(projectKey)
          } catch (e: Exception) {
            throw EncryptionError("Invalid project key format: $e")
          }
      if (decoded.size != ENCRYPTION_KEY_SIZE) {
        throw EncryptionError(
            "Invalid key size: ${decoded.size} bytes, expected $ENCRYPTION_KEY_SIZE",
        )
      }
      return PayloadEncryptor(decoded)
    }
  }
}

/**
 * encryption.go `CreateEncryptor`: null when no key is configured; an invalid key throws, mirroring
 * create_encryptor.
 */
public fun createEncryptor(projectKey: String): PayloadEncryptor? {
  if (projectKey.isEmpty()) {
    return null
  }
  return PayloadEncryptor.create(projectKey)
}

/**
 * encryption.go `canonicalJSON`: serializes data into the exact bytes Python json.dumps(data,
 * separators=(",", ":"), sort_keys=True) emits: object keys sorted recursively, compact separators,
 * and Python ensure_ascii escaping. Unknown value types render as null (the Go default branch
 * marshals best-effort and writes null on failure; a JVM analog of a channel is any unserializable
 * object).
 */
public fun canonicalJSON(data: Map<String, Any?>): String {
  val sb = StringBuilder()
  writeCanonicalJSONValue(sb, data)
  return sb.toString()
}

internal fun writeCanonicalJSONValue(
    sb: StringBuilder,
    value: Any?,
) {
  when (value) {
    null -> sb.append("null")
    is Boolean -> sb.append(if (value) "true" else "false")
    is Int,
    is Long,
    is Short,
    is Byte -> sb.append(value.toString())
    is java.math.BigInteger -> sb.append(value.toString())
    is java.math.BigDecimal -> sb.append(GoFloat.canonical(value.toDouble()))
    is Double -> sb.append(GoFloat.canonical(value))
    is Float -> sb.append(GoFloat.canonical(value.toDouble()))
    is JsonNumber -> sb.append(value.raw)
    is String -> appendCanonicalString(sb, value)
    is Instant -> appendCanonicalString(sb, rfc3339Nano(value))
    is Map<*, *> -> {
      val keys = value.keys.map { it?.toString() ?: "null" }.sorted()
      sb.append('{')
      for ((index, key) in keys.withIndex()) {
        if (index > 0) {
          sb.append(',')
        }
        appendCanonicalString(sb, key)
        sb.append(':')
        writeCanonicalJSONValue(sb, value[keyOf(key, value)])
      }
      sb.append('}')
    }
    is List<*> -> {
      sb.append('[')
      for ((index, item) in value.withIndex()) {
        if (index > 0) {
          sb.append(',')
        }
        writeCanonicalJSONValue(sb, item)
      }
      sb.append(']')
    }
    else ->
        // Best-effort fallback for other types (time values, structs); it
        // matches Python's serialization for the types the agent itself
        // places in payloads. Unserializable values render as null.
        sb.append("null")
  }
}

/**
 * encryption.go `decodeUrlsafeBase64`: accepts padded and unpadded urlsafe base64, matching the
 * Python decoder's alphabet while tolerating both padding variants.
 */
internal fun decodeUrlsafeBase64(text: String): ByteArray {
  val trimmed = text.trimEnd('=')
  return Base64.getUrlDecoder().decode(trimmed)
}

/**
 * encryption.go `encodeUrlsafeBase64`: emits padded urlsafe base64, matching Python
 * base64.urlsafe_b64encode.
 */
internal fun encodeUrlsafeBase64(data: ByteArray): String =
    Base64.getUrlEncoder().encodeToString(data)
