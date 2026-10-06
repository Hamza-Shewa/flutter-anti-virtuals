package dev.shewa.flutter_anti_virtuals

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraManager
import android.location.Location
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.net.NetworkInterface
import java.security.KeyStore
import java.security.MessageDigest

internal class ScanConfig(
    val signals: Set<String>?,
    val expectedSignatureSha256: List<String>,
    val trustedInstallers: List<String>,
    val allowedAccessibilityServices: Set<String>,
    val maxClockSkewMs: Long,
    val trustedTimeMs: Long?
) {
    companion object {
        @Suppress("UNCHECKED_CAST")
        fun from(args: Map<String, Any?>?) = ScanConfig(
            signals = (args?.get("signals") as? List<String>)?.toSet(),
            expectedSignatureSha256 = (args?.get("expectedSignatureSha256") as? List<String>).orEmpty(),
            trustedInstallers = (args?.get("trustedInstallers") as? List<String>).orEmpty(),
            allowedAccessibilityServices =
                (args?.get("allowedAccessibilityServices") as? List<String>).orEmpty().toSet(),
            maxClockSkewMs = (args?.get("maxClockSkewMs") as? Number)?.toLong() ?: 300_000L,
            trustedTimeMs = (args?.get("trustedTimeMs") as? Number)?.toLong()
        )
    }
}

internal class AntiVirtualScanner(private val context: Context) {
    private val pm: PackageManager = context.packageManager

    fun scan(config: ScanConfig): Map<String, Map<String, Any>> {
        val checks: Map<String, () -> Detection> = linkedMapOf(
            "vpn" to ::vpn,
            "proxy" to ::proxy,
            "mockLocation" to ::mockLocation,
            "virtualCamera" to ::virtualCamera,
            "developerOptions" to ::developerOptions,
            "adb" to ::adb,
            "clockTampering" to { clockTampering(config) },
            "untrustedInstaller" to { untrustedInstaller(config) },
            "signatureMismatch" to { signatureMismatch(config) },
            "accessibilityAbuse" to { accessibilityAbuse(config) },
            "remoteControlApp" to ::remoteControlApp,
            "clonedApp" to ::clonedApp,
            "userCertificates" to ::userCertificates,
            "sideloaded" to { Detection.unsupported }
        )
        return checks
            .filterKeys { config.signals == null || it in config.signals }
            .mapValues { (_, check) ->
                // One failing check must never take the whole scan down, and must not
                // look like a clean result either.
                try { check().toMap() }
                catch (t: Throwable) {
                    Detection(false, supported = false, details = listOf("check failed: ${t.javaClass.simpleName}")).toMap()
                }
            }
    }

    // ---- network -------------------------------------------------------

    private fun vpn(): Detection {
        val details = mutableListOf<String>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        try {
            @Suppress("DEPRECATION")
            cm?.allNetworks?.forEach { network ->
                val caps = cm.getNetworkCapabilities(network)
                if (caps.isVpn()) {
                    details += "network transport VPN"
                }
            }
        } catch (_: Throwable) {
        }
        try {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { it.isUp && Rules.isVirtualInterface(it.name) }
                .forEach { details += "interface ${it.name}" }
        } catch (_: Throwable) {
        }
        return Detection.of(details.distinct())
    }

    private fun proxy(): Detection {
        val details = mutableListOf<String>()
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        try {
            cm?.defaultProxy?.let { p ->
                if (!p.host.isNullOrBlank()) details += "system proxy ${p.host}:${p.port}"
                if (p.pacFileUrl != null && p.pacFileUrl.toString().isNotBlank()) {
                    details += "PAC file ${p.pacFileUrl}"
                }
            }
        } catch (_: Throwable) {
        }
        for (key in listOf("http", "https")) {
            val host = System.getProperty("$key.proxyHost")
            val port = System.getProperty("$key.proxyPort")
            if (!host.isNullOrBlank() && port != null && port != "-1") {
                details += "$key.proxy $host:$port"
            }
        }
        return Detection.of(details.distinct())
    }

    private fun userCertificates(): Detection {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val users = store.aliases().toList().filter { it.startsWith("user:") }
        return Detection.of(users.map { "user CA $it" })
    }

    // ---- location & camera ---------------------------------------------

    @SuppressLint("MissingPermission")
    private fun mockLocation(): Detection {
        val details = mutableListOf<String>()
        val granted =
            context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED ||
                context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
        if (granted) {
            val lm = context.getSystemService(Context.LOCATION_SERVICE) as? LocationManager
            lm?.getProviders(true)?.forEach { provider ->
                val loc: Location? = try { lm.getLastKnownLocation(provider) } catch (_: Throwable) { null }
                if (loc != null && isMock(loc) && Rules.isRecentFix(ageMs(loc))) {
                    details += "mock location from provider $provider"
                }
            }
        }
        details += installed(KnownPackages.mockLocation).map { "mock app $it" }
        return Detection.of(details.distinct())
    }

    /** How long ago the fix was made, or null when the provider did not stamp it. */
    private fun ageMs(location: Location): Long? =
        location.elapsedRealtimeNanos.takeIf { it > 0 }
            ?.let { (SystemClock.elapsedRealtimeNanos() - it) / 1_000_000 }

    private fun isMock(location: Location): Boolean =
        if (Build.VERSION.SDK_INT >= 31) location.isMock
        else @Suppress("DEPRECATION") location.isFromMockProvider

    private fun virtualCamera(): Detection {
        val details = installed(KnownPackages.virtualCamera).map { "virtual camera app $it" }.toMutableList()
        val cm = context.getSystemService(Context.CAMERA_SERVICE) as? CameraManager
        try {
            cm?.cameraIdList?.forEach { id ->
                try {
                    val facing = cm.getCameraCharacteristics(id).get(CameraCharacteristics.LENS_FACING)
                    if (facing == CameraCharacteristics.LENS_FACING_EXTERNAL) {
                        details += "external camera $id"
                    }
                } catch (_: Throwable) {
                }
            }
        } catch (_: Throwable) {
        }
        return Detection.of(details)
    }

    // ---- device state ---------------------------------------------------

    private fun globalInt(name: String): Int? = try {
        Settings.Global.getInt(context.contentResolver, name)
    } catch (_: Throwable) { null }

    private fun developerOptions(): Detection =
        Detection.of(if (globalInt(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED) == 1) listOf("developer options enabled") else emptyList())

    private fun adb(): Detection {
        val details = mutableListOf<String>()
        if (globalInt(Settings.Global.ADB_ENABLED) == 1) details += "USB debugging enabled"
        if (Build.VERSION.SDK_INT >= 30 && globalInt("adb_wifi_enabled") == 1) details += "wireless debugging enabled"
        return Detection.of(details)
    }

    private fun clockTampering(config: ScanConfig): Detection {
        val details = Rules.clockDetails(
            autoTime = globalInt(Settings.Global.AUTO_TIME)?.let { it == 1 },
            autoTimeZone = globalInt(Settings.Global.AUTO_TIME_ZONE)?.let { it == 1 },
            deviceMs = System.currentTimeMillis(),
            trustedMs = config.trustedTimeMs,
            maxSkewMs = config.maxClockSkewMs
        )
        return Detection.of(details)
    }

    // ---- app integrity --------------------------------------------------

    private fun ownInfo(flags: Int = 0): PackageInfo =
        if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(flags.toLong()))
        else @Suppress("DEPRECATION") pm.getPackageInfo(context.packageName, flags)

    private fun untrustedInstaller(config: ScanConfig): Detection {
        // No debuggable exemption: a repackaged APK can set the flag itself. Builds
        // installed by tooling report no installer; exclude the signal in debug builds
        // from the Dart side if that is unwanted.
        val installer = if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(context.packageName).installingPackageName
        else @Suppress("DEPRECATION") pm.getInstallerPackageName(context.packageName)
        return if (Rules.isUntrustedInstaller(installer, config.trustedInstallers)) {
            Detection(true, details = listOf("installer: ${installer ?: "none (sideloaded)"}"))
        } else Detection(false)
    }

    @Suppress("DEPRECATION")
    private fun signatureMismatch(config: ScanConfig): Detection {
        if (config.expectedSignatureSha256.isEmpty()) return Detection.unsupported
        val digests = mutableListOf<String>()
        val info = ownInfo(if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES)
        val sigs = if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo?.let { if (it.hasMultipleSigners()) it.apkContentsSigners else it.signingCertificateHistory }
        } else info.signatures
        sigs?.forEach { s ->
            digests += MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }
        }
        return if (Rules.signatureMatches(digests, config.expectedSignatureSha256)) Detection(false)
        else Detection(true, details = digests.map { "unexpected certificate $it" })
    }

    private fun clonedApp(): Detection {
        val details = mutableListOf<String>()
        val userId = Process.myUid() / 100000
        val dataDir = context.applicationInfo.dataDir
        if (Rules.isClonedDataDir(dataDir, context.packageName, userId)) details += "unexpected data dir $dataDir"
        details += installed(KnownPackages.cloners).map { "cloner/virtual space $it" }
        try {
            val cmdline = File("/proc/self/cmdline").readText().trim('\u0000').substringBefore(':')
            if (cmdline.isNotEmpty() && cmdline != context.packageName) details += "process name $cmdline"
        } catch (_: Throwable) {
        }
        return Detection.of(details)
    }

    // ---- abuse of accessibility / remote control -------------------------

    private fun accessibilityAbuse(config: ScanConfig): Detection {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
            ?: return Detection.unsupported
        val details = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .filter { svc ->
                val appInfo = svc.resolveInfo.serviceInfo.applicationInfo
                val system = appInfo.flags and ApplicationInfo.FLAG_SYSTEM != 0
                val readsScreen = svc.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT != 0
                val pkg = svc.resolveInfo.serviceInfo.packageName
                !system && readsScreen && pkg != context.packageName && pkg !in config.allowedAccessibilityServices
            }
            .map { "accessibility service ${it.resolveInfo.serviceInfo.packageName}" }
        return Detection.of(details)
    }

    private fun remoteControlApp(): Detection =
        Detection.of(installed(KnownPackages.remoteControl).map { "remote control app $it" })

    // ---- helpers ----------------------------------------------------------

    private fun installed(candidates: Set<String>): List<String> = candidates.filter { pkg ->
        try {
            if (Build.VERSION.SDK_INT >= 33) pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
            else @Suppress("DEPRECATION") pm.getPackageInfo(pkg, 0)
            true
        } catch (_: PackageManager.NameNotFoundException) { false }
    }
}
