package dev.shewa.flutter_anti_virtuals

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/** Pure helpers for the device-bound signature, unit tested without Android. */
internal object DeviceKeyRules {
    /** The attestation challenge for [nonce]: its SHA-256, so any nonce length fits. */
    fun challenge(nonce: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(nonce.toByteArray(Charsets.UTF_8))

    /** A key attestation chain has the attested leaf plus at least one issuer. */
    fun isAttested(chainLength: Int): Boolean = chainLength > 1

    fun protection(strongBox: Boolean, hardware: Boolean): String = when {
        strongBox -> "strongBox"
        hardware -> "hardware"
        else -> "software"
    }
}

/**
 * Signs a payload with an EC key that is created for this one request, attested with the nonce as
 * challenge, and deleted again. A fresh key per request means the attestation proves the request
 * is live, not replayed from an earlier session.
 */
internal object DeviceKey {
    private const val PROVIDER = "AndroidKeyStore"

    fun sign(nonce: String, payload: ByteArray): Map<String, Any> {
        val alias = "flutter_anti_virtuals.verify." + UUID.randomUUID()
        val store = KeyStore.getInstance(PROVIDER).apply { load(null) }
        try {
            val challenge = DeviceKeyRules.challenge(nonce)
            // StrongBox first, then the TEE, then without attestation (devices that cannot do it).
            val attempts = buildList {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) add(Attempt(challenge, true))
                add(Attempt(challenge, false))
                add(Attempt(null, false))
            }
            var failure: Exception? = null
            for (attempt in attempts) {
                try {
                    store.deleteEntry(alias)
                    return signWith(store, alias, attempt, payload)
                } catch (e: Exception) {
                    failure = e
                }
            }
            throw failure ?: IllegalStateException("no key could be created")
        } finally {
            try {
                store.deleteEntry(alias)
            } catch (_: Exception) {
            }
        }
    }

    private class Attempt(val challenge: ByteArray?, val strongBox: Boolean)

    private fun signWith(store: KeyStore, alias: String, attempt: Attempt, payload: ByteArray): Map<String, Any> {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (attempt.challenge != null) builder.setAttestationChallenge(attempt.challenge)
        if (attempt.strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        generator.initialize(builder.build())
        val pair: KeyPair = generator.generateKeyPair()

        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(payload)
        val signature = signer.sign()

        val chain = if (attempt.challenge != null) {
            store.getCertificateChain(alias)?.map { Base64.encodeToString(it.encoded, Base64.NO_WRAP) }.orEmpty()
        } else {
            emptyList()
        }
        return mapOf(
            "signature" to Base64.encodeToString(signature, Base64.NO_WRAP),
            "publicKey" to Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP),
            "algorithm" to "SHA256withECDSA",
            "protection" to protectionOf(pair, attempt.strongBox),
            "attested" to DeviceKeyRules.isAttested(chain.size),
            "certificateChain" to chain
        )
    }

    private fun protectionOf(pair: KeyPair, strongBoxRequested: Boolean): String {
        val info = try {
            KeyFactory.getInstance(pair.private.algorithm, PROVIDER)
                .getKeySpec(pair.private, KeyInfo::class.java)
        } catch (_: Exception) {
            null
        }
        val level = if (info != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) info.securityLevel else null
        val strongBox = level == KeyProperties.SECURITY_LEVEL_STRONGBOX ||
            (level == null && strongBoxRequested)
        @Suppress("DEPRECATION")
        val hardware = level == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
            (level == null && info?.isInsideSecureHardware == true)
        return DeviceKeyRules.protection(strongBox, hardware)
    }
}
