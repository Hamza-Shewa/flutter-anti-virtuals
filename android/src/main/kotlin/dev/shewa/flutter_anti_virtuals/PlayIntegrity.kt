package dev.shewa.flutter_anti_virtuals

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import java.security.MessageDigest

/** Pure helpers for the Play Integrity request, unit tested without Android. */
internal object PlayIntegrityRules {
    /** SHA-256 of the signed payload, which the Play Integrity nonce has to carry. */
    fun binding(payload: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(Charsets.UTF_8))
}

internal object PlayIntegrity {
    /**
     * Requests a classic Play Integrity token whose nonce is the URL-safe base64 (no padding) of
     * [PlayIntegrityRules.binding]. The token is decoded by the backend, never on the device.
     */
    fun request(
        context: Context,
        payload: String,
        cloudProjectNumber: Long?,
        onResult: (Result<Map<String, Any>>) -> Unit
    ) {
        try {
            val nonce = Base64.encodeToString(
                PlayIntegrityRules.binding(payload),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )
            val request = IntegrityTokenRequest.builder().setNonce(nonce).apply {
                if (cloudProjectNumber != null) setCloudProjectNumber(cloudProjectNumber)
            }.build()
            IntegrityManagerFactory.create(context.applicationContext)
                .requestIntegrityToken(request)
                .addOnSuccessListener { response ->
                    onResult(Result.success(mapOf("type" to "playIntegrity", "token" to response.token())))
                }
                .addOnFailureListener { error -> onResult(Result.failure(error)) }
        } catch (e: Exception) {
            onResult(Result.failure(e))
        }
    }
}
