package dev.shewa.flutter_anti_virtuals

import android.app.Activity
import android.content.Context
import android.media.AudioManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.UUID
import javax.crypto.KeyGenerator

/** Pure rules of the fraud-context checks, kept free of Android types so they can be unit tested. */
internal object FraudRules {
    /** What the audio mode says about calls. A cellular call and a VoIP call set different modes. */
    fun callDetails(audioMode: Int): List<String> = when (audioMode) {
        AudioManager.MODE_IN_CALL, AudioManager.MODE_CALL_SCREENING, AudioManager.MODE_CALL_REDIRECT ->
            listOf("phone call in progress")
        AudioManager.MODE_IN_COMMUNICATION, AudioManager.MODE_COMMUNICATION_REDIRECT ->
            listOf("voice or video call in progress")
        else -> emptyList()
    }

    fun screenLockDetails(deviceSecure: Boolean): List<String> =
        if (deviceSecure) emptyList() else listOf("no PIN, pattern or password is set")

    /**
     * Where the app's data stands. [boundId] is the id kept in the app's data; [hasDeviceKey] says
     * whether this device holds the key created for it.
     */
    fun binding(boundId: String?, hasDeviceKey: (String) -> Boolean): BindingState = when {
        boundId == null -> BindingState.UNBOUND
        hasDeviceKey(boundId) -> BindingState.BOUND
        else -> BindingState.MIGRATED
    }
}

internal enum class BindingState { UNBOUND, BOUND, MIGRATED }

/**
 * Notices app data that was created on another device: restored from a backup, moved by a device
 * transfer or copied off a rooted phone. A random id in the app's shared preferences, which
 * backups and transfers carry, is paired with an Android Keystore key named after it, which never
 * leaves the device. Data whose id has no key here came from somewhere else.
 *
 * Not thread safe; the plugin calls it from its single worker thread.
 */
internal class DeviceBinding(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    fun check(): Detection {
        val id = prefs.getString(ID, null)
        return when (FraudRules.binding(id, this::hasKey)) {
            BindingState.UNBOUND -> {
                bind()
                Detection(false)
            }
            BindingState.BOUND -> Detection(false)
            BindingState.MIGRATED -> Detection.of(listOf("app data was created on another device or restored from a backup"))
        }
    }

    /** Accepts the current data on this device: the old binding is dropped and a new one made. */
    fun rebind() {
        prefs.getString(ID, null)?.let { old ->
            try { keyStore().deleteEntry(alias(old)) } catch (_: Exception) {}
        }
        bind()
    }

    private fun bind() {
        val id = UUID.randomUUID().toString()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply {
            init(
                KeyGenParameterSpec.Builder(alias(id), KeyProperties.PURPOSE_ENCRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .build()
            )
        }.generateKey()
        // commit, not apply: the next scan may run before an apply would have been written.
        prefs.edit().putString(ID, id).commit()
    }

    private fun hasKey(id: String): Boolean = keyStore().containsAlias(alias(id))

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun alias(id: String) = "dev.shewa.flutter_anti_virtuals.binding.$id"

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val PREFERENCES = "dev.shewa.flutter_anti_virtuals.binding"
        const val ID = "id"
    }
}

/** Calls [onChange] when a call starts or ends (Android 12+). */
internal class CallWatcher(context: Context, private val onChange: () -> Unit) {
    private val context = context.applicationContext
    private val audio = context.getSystemService(Context.AUDIO_SERVICE) as? AudioManager
    private var listener: Any? = null

    fun start() {
        if (Build.VERSION.SDK_INT < 31 || audio == null) return
        val next = AudioManager.OnModeChangedListener { onChange() }
        audio.addOnModeChangedListener(context.mainExecutor, next)
        listener = next
    }

    fun stop() {
        if (Build.VERSION.SDK_INT < 31) return
        val current = listener as? AudioManager.OnModeChangedListener ?: return
        listener = null
        try { audio?.removeOnModeChangedListener(current) } catch (_: Throwable) {}
    }
}

/**
 * Reports screenshots taken while the activity is visible (Android 14+). Needs the
 * DETECT_SCREEN_CAPTURE permission, which the plugin's manifest declares. The callback is only
 * registered while someone listens, because Android tells the user that the app noticed.
 */
internal class ScreenshotWatcher {
    private var activity: Activity? = null
    private var listener: (() -> Unit)? = null
    private var callback: Any? = null

    fun attach(next: Activity) {
        unregister()
        activity = next
        register()
    }

    fun detach() {
        unregister()
        activity = null
    }

    fun listen(onScreenshot: () -> Unit) {
        unregister()
        listener = onScreenshot
        register()
    }

    fun stop() {
        unregister()
        listener = null
    }

    private fun register() {
        if (Build.VERSION.SDK_INT < 34) return
        val current = activity ?: return
        val onScreenshot = listener ?: return
        try {
            val next = Activity.ScreenCaptureCallback { onScreenshot() }
            current.registerScreenCaptureCallback(current.mainExecutor, next)
            callback = next
        } catch (_: Throwable) {
        }
    }

    private fun unregister() {
        if (Build.VERSION.SDK_INT < 34) return
        val current = callback as? Activity.ScreenCaptureCallback ?: return
        callback = null
        try { activity?.unregisterScreenCaptureCallback(current) } catch (_: Throwable) {}
    }
}
