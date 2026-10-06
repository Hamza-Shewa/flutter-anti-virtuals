package dev.shewa.flutter_anti_virtuals

import java.util.Locale

/** Everything the root check looks at, collected on the device. */
internal data class RootEvidence(
    /** `Build.TAGS`. */
    val tags: String = "",
    val fingerprint: String = "",
    /** System properties, see [RootRules.PROPERTIES]. */
    val properties: Map<String, String> = emptyMap(),
    /** Full paths of [RootRules.BINARIES] found in the `PATH` directories and [RootRules.BINARY_DIRECTORIES]. */
    val binaries: Set<String> = emptySet(),
    /** Paths from [RootRules.FILES] that exist. */
    val existingFiles: Set<String> = emptySet(),
    /** Packages from [KnownPackages.root] that are installed. */
    val installedPackages: Set<String> = emptySet(),
    /** Lines of `/proc/mounts`, or null when it could not be read. */
    val mounts: List<String>? = null,
    /** Content of `/sys/fs/selinux/enforce`, or null when it cannot be read (the usual case). */
    val selinuxEnforce: String? = null
)

/**
 * Pure root classifier, kept free of Android types so it can be unit tested.
 *
 * Real devices must never be reported, so evidence is split in two. A strong indicator is
 * something a stock, unrooted device does not have (an `su` binary, a root manager app, a
 * writable system partition, `adbd` running as root, SELinux in permissive mode, Magisk or
 * KernelSU mounts) and is enough on its own. A weak indicator (a debug build of the system, an
 * unlocked bootloader) also shows up on unrooted developer devices and custom ROMs, so both are
 * needed. The several signs of a debug build count once.
 *
 * Root-hiding tools (Zygisk DenyList, Shamiko, hooks) remove most of this evidence for a
 * targeted app. Treat the result as a signal, and verify with Play Integrity on the server.
 */
internal object RootRules {
    const val WEAK_THRESHOLD = 2

    val PROPERTIES = listOf(
        "ro.debuggable",
        "ro.secure",
        "ro.build.type",
        "ro.build.tags",
        "service.adb.root",
        "ro.boot.verifiedbootstate",
        "ro.boot.flash.locked",
        "ro.boot.vbmeta.device_state"
    )

    /** Binary names that only exist on rooted devices. */
    val BINARIES = listOf("su", "daemonsu", "magisk", "magiskpolicy", "resetprop")

    /** Looked at in addition to the directories of `PATH`. */
    val BINARY_DIRECTORIES = listOf(
        "/system/bin", "/system/xbin", "/system/sbin", "/system/bin/failsafe", "/system/bin/.ext",
        "/system/sd/xbin", "/vendor/bin", "/sbin", "/su/bin", "/data/local", "/data/local/bin",
        "/data/local/xbin"
    )

    /**
     * Files left by root tools and visible to an app. The Magisk and KernelSU directories under
     * `/data/adb` are not listed: an app cannot see them, so they never match.
     */
    val FILES = listOf(
        "/system/app/Superuser.apk",
        "/system/app/SuperSU",
        "/system/app/SuperSU.apk",
        "/system/etc/init.d/99SuperSUDaemon",
        "/system/usr/we-need-root",
        "/sbin/.magisk",
        "/sbin/.core",
        "/dev/com.koushikdutta.superuser.daemon"
    )

    /** System partitions that are read-only on an unrooted device. */
    private val readOnlyMounts = setOf("/system", "/system_ext", "/vendor", "/product")

    /** Names of root frameworks in the device or mount point of a mount. */
    private val mountTokens = listOf("magisk", "ksu", "apatch")

    fun details(e: RootEvidence): List<String> {
        val strong = mutableListOf<String>()
        val weak = mutableListOf<String>()
        val props = e.properties.mapValues { it.value.norm() }

        // ---- strong ----
        e.binaries.sorted().forEach { strong += "root binary $it" }
        e.existingFiles.sorted().forEach { strong += "root file $it" }
        e.installedPackages.sorted().forEach { strong += "root app $it" }
        if (props["service.adb.root"] == "1") strong += "adbd runs as root"
        if (props["ro.secure"] == "0") strong += "ro.secure=0"
        if (e.selinuxEnforce?.trim() == "0") strong += "SELinux is permissive"
        for (line in e.mounts.orEmpty()) {
            val fields = line.trim().split(Regex("\\s+"))
            if (fields.size < 4) continue
            val (device, point, _, options) = fields
            if (point in readOnlyMounts && options.split(',').firstOrNull() == "rw") {
                strong += "writable $point"
            }
            val named = listOf(device, point).map { it.norm() }
            // Whole path segments, so "/mnt/ksulu" is not a KernelSU mount.
            val token = mountTokens.firstOrNull { t ->
                named.any { name -> name.split('/').any { it == t || it == ".$t" } }
            }
            if (token != null) strong += "$token mount $point"
        }

        // ---- weak ----
        val tags = (e.tags.norm() + " " + props["ro.build.tags"].orEmpty()).trim()
        val debugBuild = listOf(
            "test-keys" in tags,
            "dev-keys" in tags,
            props["ro.debuggable"] == "1",
            props["ro.build.type"] in listOf("userdebug", "eng")
        )
        if (debugBuild.any { it }) weak += "debug build of the system"
        if (props["ro.boot.verifiedbootstate"] == "orange" || props["ro.boot.flash.locked"] == "0" ||
            props["ro.boot.vbmeta.device_state"] == "unlocked"
        ) weak += "unlocked bootloader"

        val detected = strong.isNotEmpty() || weak.size >= WEAK_THRESHOLD
        return if (detected) (strong + weak).distinct() else emptyList()
    }

    private fun String.norm(): String = trim().lowercase(Locale.ROOT)
}
