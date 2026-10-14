package dev.shewa.flutter_anti_virtuals

import android.content.Context
import android.util.Base64
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.PrepareIntegrityTokenRequest
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenProvider
import com.google.android.play.core.integrity.StandardIntegrityManager.StandardIntegrityTokenRequest
import java.security.MessageDigest

/** Pure helpers for the Play Integrity request, unit tested without Android. */
internal object PlayIntegrityRules {
    /**
     * SHA-256 of the signed payload. Its URL-safe base64 (no padding) is the nonce of a classic
     * request and the request hash of a standard one.
     */
    fun binding(payload: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(payload.toByteArray(Charsets.UTF_8))
}

/**
 * One prepared value per key, shared by every request for that key. A key is prepared at most
 * once at a time: requests that arrive while it is being prepared wait for the same result.
 *
 * Not thread safe. The plugin uses it on the main thread, where its method calls and the Play
 * tasks' callbacks run.
 */
internal class PreparedCache<K, V>(private val prepare: (K, (Result<V>) -> Unit) -> Unit) {
    private val ready = HashMap<K, V>()
    private val waiting = HashMap<K, MutableList<(Result<V>) -> Unit>>()

    fun get(key: K, onResult: (Result<V>) -> Unit) {
        ready[key]?.let { return onResult(Result.success(it)) }
        waiting[key]?.let { it += onResult; return }
        waiting[key] = mutableListOf(onResult)
        val finish: (Result<V>) -> Unit = { outcome ->
            outcome.onSuccess { ready[key] = it }
            waiting.remove(key)?.forEach { it(outcome) }
        }
        try {
            prepare(key, finish)
        } catch (e: Exception) {
            finish(Result.failure(e))
        }
    }

    /**
     * Runs [use] with the value for [key]. When a value that was already cached fails, it may have
     * gone stale (Play reports an expired token provider this way), so it is dropped, prepared
     * again and [use] runs once more. A failure with a freshly prepared value is final.
     */
    fun <T> use(key: K, action: (V, (Result<T>) -> Unit) -> Unit, onResult: (Result<T>) -> Unit) {
        val cached = ready.containsKey(key)
        get(key) { first ->
            val value = first.getOrElse { return@get onResult(Result.failure(it)) }
            action(value) { outcome ->
                if (outcome.isSuccess || !cached) return@action onResult(outcome)
                if (ready[key] === value) ready.remove(key)
                get(key) { second ->
                    second.fold(onSuccess = { action(it, onResult) }, onFailure = { onResult(Result.failure(it)) })
                }
            }
        }
    }
}

/**
 * Play Integrity tokens bound to a signed payload. The backend decodes them with Google; the
 * device never does. See doc/server-verification.md.
 */
internal class PlayIntegrity(context: Context) {
    private val context = context.applicationContext
    private val providers = PreparedCache<Long, StandardIntegrityTokenProvider> { project, done ->
        val request = PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(project).build()
        IntegrityManagerFactory.createStandard(this.context)
            .prepareIntegrityToken(request)
            .addOnSuccessListener { done(Result.success(it)) }
            .addOnFailureListener { done(Result.failure(it)) }
    }

    /**
     * Warms up standard requests for [cloudProjectNumber]. Preparing takes a few seconds, so apps
     * do it well before the first [requestStandard], for example at startup.
     */
    fun prepare(cloudProjectNumber: Long, onResult: (Result<Unit>) -> Unit) =
        providers.get(cloudProjectNumber) { outcome -> onResult(outcome.map { }) }

    /**
     * A standard request: fast once prepared and with a much higher quota than a classic one. The
     * token's request hash is the URL-safe base64 (no padding) of [PlayIntegrityRules.binding].
     */
    fun requestStandard(payload: String, cloudProjectNumber: Long, onResult: (Result<Map<String, Any>>) -> Unit) {
        val hash = encode(PlayIntegrityRules.binding(payload))
        val request = StandardIntegrityTokenRequest.builder().setRequestHash(hash).build()
        providers.use<Map<String, Any>>(
            cloudProjectNumber,
            action = { provider, done ->
                provider.request(request)
                    .addOnSuccessListener { done(Result.success(tokenMap(it.token(), standard = true))) }
                    .addOnFailureListener { done(Result.failure(it)) }
            },
            onResult = onResult
        )
    }

    /**
     * A classic request whose nonce is the URL-safe base64 (no padding) of
     * [PlayIntegrityRules.binding]. Slower and with a lower quota; meant for rare, high-value
     * actions.
     */
    fun requestClassic(payload: String, cloudProjectNumber: Long?, onResult: (Result<Map<String, Any>>) -> Unit) {
        try {
            val request = IntegrityTokenRequest.builder().setNonce(encode(PlayIntegrityRules.binding(payload))).apply {
                if (cloudProjectNumber != null) setCloudProjectNumber(cloudProjectNumber)
            }.build()
            IntegrityManagerFactory.create(context)
                .requestIntegrityToken(request)
                .addOnSuccessListener { onResult(Result.success(tokenMap(it.token(), standard = false))) }
                .addOnFailureListener { onResult(Result.failure(it)) }
        } catch (e: Exception) {
            onResult(Result.failure(e))
        }
    }

    private fun encode(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    private fun tokenMap(token: String, standard: Boolean): Map<String, Any> =
        mapOf("type" to "playIntegrity", "token" to token, "standard" to standard)
}
