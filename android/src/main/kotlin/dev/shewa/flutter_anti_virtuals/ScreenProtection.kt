package dev.shewa.flutter_anti_virtuals

import android.app.Activity
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.os.Handler
import android.view.Window
import android.view.WindowManager

/** What `setScreenProtection` asked for. */
internal data class ScreenProtectionConfig(
    val secureWindow: Boolean = false,
    val filterObscuredTouches: Boolean = false,
    val hideOverlayWindows: Boolean = false
) {
    companion object {
        fun from(map: Map<String, Any?>?) = ScreenProtectionConfig(
            secureWindow = map?.get("secureWindow") == true,
            filterObscuredTouches = map?.get("filterObscuredTouches") == true,
            hideOverlayWindows = map?.get("hideOverlayWindows") == true
        )
    }
}

/** Pure part of the screen capture check, kept free of Android types so it can be unit tested. */
internal object CaptureRules {
    fun details(presentationDisplays: List<String>, screenRecording: Boolean?): List<String> {
        val details = mutableListOf<String>()
        presentationDisplays.sorted().forEach { details += "external display $it" }
        if (screenRecording == true) details += "screen is being recorded"
        return details
    }
}

/** A window setting together with whether the plugin is the one that turned it on. */
internal data class OwnedSetting(val value: Boolean, val owned: Boolean)

/**
 * Pure ownership rule for one window setting: turn it on when asked, and on release only turn
 * off what the plugin itself turned on, so a flag the host app set (`FLAG_SECURE` in its own
 * `onCreate`, another screen-protection package) survives `unprotectScreen()`.
 */
internal object ProtectionRules {
    fun next(wanted: Boolean, current: Boolean, owned: Boolean): OwnedSetting = when {
        wanted && current -> OwnedSetting(true, owned)
        wanted -> OwnedSetting(true, true)
        owned -> OwnedSetting(false, false)
        else -> OwnedSetting(current, false)
    }
}

/** Screen recording state reported by the system to the foreground activity (Android 15+). */
internal object ScreenCaptureState {
    @Volatile
    var recording: Boolean? = null
}

/**
 * Applies the window protections to the current activity and keeps them across configuration
 * changes by re-applying them when an activity is attached.
 */
internal class ScreenProtector {
    private var activity: Activity? = null
    private var config = ScreenProtectionConfig()
    // What the plugin turned on in [ownedWindow]; reset when a new window is attached.
    private var ownedWindow: Window? = null
    private var ownsSecure = false
    private var ownsTouchFilter = false
    private var ownsHiddenOverlays = false
    private var recordingCallback: java.util.function.Consumer<Int>? = null
    private var onChange: () -> Unit = {}

    /** Returns true when the protections were applied to a live activity. */
    fun apply(next: ScreenProtectionConfig): Boolean {
        config = next
        val current = activity ?: return false
        applyTo(current)
        return true
    }

    fun attach(next: Activity, changed: () -> Unit) {
        activity = next
        onChange = changed
        applyTo(next)
        registerRecordingCallback(next)
    }

    fun detach() {
        unregisterRecordingCallback()
        activity = null
        ScreenCaptureState.recording = null
    }

    private fun applyTo(a: Activity) {
        val window = a.window
        if (window !== ownedWindow) {
            ownedWindow = window
            ownsSecure = false
            ownsTouchFilter = false
            ownsHiddenOverlays = false
        }
        val flag = WindowManager.LayoutParams.FLAG_SECURE
        val secure = ProtectionRules.next(
            config.secureWindow, window.attributes.flags and flag != 0, ownsSecure
        )
        if (secure.value) window.addFlags(flag) else window.clearFlags(flag)
        ownsSecure = secure.owned

        val view = window.decorView
        val touches = ProtectionRules.next(
            config.filterObscuredTouches, view.filterTouchesWhenObscured, ownsTouchFilter
        )
        view.filterTouchesWhenObscured = touches.value
        ownsTouchFilter = touches.owned

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            // There is no getter, so only what the plugin set is known to be on.
            val overlays = ProtectionRules.next(config.hideOverlayWindows, ownsHiddenOverlays, ownsHiddenOverlays)
            try {
                // Needs the HIDE_OVERLAY_WINDOWS permission, which the plugin's manifest declares.
                if (overlays.value != ownsHiddenOverlays) window.setHideOverlayWindows(overlays.value)
                ownsHiddenOverlays = overlays.owned
            } catch (_: SecurityException) {
            }
        }
    }

    private fun registerRecordingCallback(a: Activity) {
        if (Build.VERSION.SDK_INT < 35) return
        unregisterRecordingCallback()
        try {
            val callback = java.util.function.Consumer<Int> { state ->
                ScreenCaptureState.recording = state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
                onChange()
            }
            val initial = a.windowManager.addScreenRecordingCallback(a.mainExecutor, callback)
            ScreenCaptureState.recording = initial == WindowManager.SCREEN_RECORDING_STATE_VISIBLE
            recordingCallback = callback
        } catch (_: Throwable) {
            // Needs DETECT_SCREEN_RECORDING (declared by the plugin); older devices have no callback.
        }
    }

    private fun unregisterRecordingCallback() {
        val callback = recordingCallback ?: return
        recordingCallback = null
        try {
            if (Build.VERSION.SDK_INT >= 35) activity?.windowManager?.removeScreenRecordingCallback(callback)
        } catch (_: Throwable) {
        }
    }
}

/** Calls [onChange] when a display is connected, disconnected or changed (HDMI, Miracast, Cast). */
internal class DisplayWatcher(context: Context, private val handler: Handler, private val onChange: () -> Unit) {
    private val manager = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
    private val listener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = onChange()
        override fun onDisplayRemoved(displayId: Int) = onChange()
        override fun onDisplayChanged(displayId: Int) = Unit
    }

    fun start() {
        manager?.registerDisplayListener(listener, handler)
    }

    fun stop() {
        manager?.unregisterDisplayListener(listener)
    }
}
