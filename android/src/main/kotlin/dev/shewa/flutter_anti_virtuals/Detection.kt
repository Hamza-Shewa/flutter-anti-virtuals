package dev.shewa.flutter_anti_virtuals

/** Outcome of one check, converted to a map for the platform channel. */
internal data class Detection(
    val detected: Boolean,
    val supported: Boolean = true,
    val details: List<String> = emptyList(),
    /** The part of [details] that only says a known tool is installed, not that it is in use. */
    val installedApps: List<String> = emptyList(),
    /** Set when the check threw: the answer is unknown, which is not the same as clean. */
    val error: String? = null
) {
    fun toMap(): Map<String, Any> = buildMap {
        put("detected", detected)
        put("supported", supported)
        put("details", details)
        if (installedApps.isNotEmpty()) put("installedApps", installedApps)
        if (error != null) {
            put("failed", true)
            put("error", error)
        }
    }

    companion object {
        val unsupported = Detection(detected = false, supported = false)
        fun of(details: List<String>) = Detection(details.isNotEmpty(), details = details)

        /** Active evidence plus installed tools; either one is a detection. */
        fun of(active: List<String>, installedApps: List<String>): Detection {
            val details = (active + installedApps).distinct()
            return Detection(details.isNotEmpty(), details = details, installedApps = installedApps.distinct())
        }

        fun failed(error: Throwable) = Detection(false, error = "check failed: ${error.javaClass.simpleName}")
    }
}

/** Pure decision logic, kept free of Android types so it can be unit tested. */
internal object Rules {
    fun clockDetails(
        autoTime: Boolean?,
        autoTimeZone: Boolean?,
        deviceMs: Long,
        trustedMs: Long?,
        maxSkewMs: Long
    ): List<String> = buildList {
        if (autoTime == false) add("automatic date & time is off")
        if (autoTimeZone == false) add("automatic time zone is off")
        if (trustedMs != null) {
            val skew = kotlin.math.abs(deviceMs - trustedMs)
            if (skew > maxSkewMs) add("clock differs from trusted time by ${skew}ms")
        }
    }

    fun signatureMatches(actualSha256: Collection<String>, expected: Collection<String>): Boolean {
        val wanted = expected.map { it.replace(":", "").lowercase() }.toSet()
        return actualSha256.any { it.lowercase() in wanted }
    }

    fun isUntrustedInstaller(installer: String?, trusted: Collection<String>): Boolean =
        installer == null || installer !in trusted

    /**
     * Packages that can claim any installer name. Only the shell (and root, which `rooted`
     * reports) may pass an arbitrary `installerPackageName`, as in
     * `adb install -i com.android.vending`; a normal app can only name itself.
     */
    val SPOOFING_INITIATORS = setOf("com.android.shell", "shell", "root")

    /**
     * Android 11+ records two installers: `installingPackageName`, which the caller chooses, and
     * `initiatingPackageName`, the app that actually started the install. An install started
     * from the shell that claims an installer is reported even when the claimed one is trusted.
     *
     * Other initiators are not checked against [trusted]: legitimate installs are started by
     * apps such as the device restore or setup wizard on behalf of the store, which would
     * otherwise flag every phone set up from a backup.
     */
    fun untrustedInstallerDetails(
        installing: String?,
        initiating: String?,
        trusted: Collection<String>
    ): List<String> = buildList {
        if (isUntrustedInstaller(installing, trusted)) add("installer: ${installing ?: "none (sideloaded)"}")
        if (installing != null && initiating != null && initiating in SPOOFING_INITIATORS) {
            add("installer $installing claimed by an install from $initiating")
        }
    }

    fun isClonedDataDir(dataDir: String, packageName: String, userId: Int): Boolean {
        val expected = setOf(
            "/data/user/$userId/$packageName",
            "/data/data/$packageName",
            "/data/user_de/$userId/$packageName"
        )
        val dir = dataDir.trimEnd('/')
        if (dir in expected) return false
        // Apps moved to adopted (portable) storage live under /mnt/expand/<uuid>/.
        val adopted = Regex("^/mnt/expand/[^/]+/(user|user_de)/\\d+/${Regex.escape(packageName)}$")
        return !adopted.matches(dir)
    }

    /**
     * Android keeps the last fix of every provider, so a mock fix stays visible long after the
     * spoofing app stopped (or its test provider was removed). A running mock app injects a new
     * fix about every second, so only a recent one counts. A fix of unknown age counts.
     */
    const val MOCK_FIX_MAX_AGE_MS = 120_000L

    fun isRecentFix(ageMs: Long?, maxAgeMs: Long = MOCK_FIX_MAX_AGE_MS): Boolean =
        ageMs == null || ageMs <= maxAgeMs

    fun isVirtualInterface(name: String): Boolean {
        val n = name.lowercase()
        // `ipsec*` is deliberately absent: Wi-Fi Calling / VoLTE keep those up.
        return n.startsWith("tun") || n.startsWith("ppp") || n.startsWith("tap") ||
            n.startsWith("wg") || n.startsWith("pptp")
    }
}
