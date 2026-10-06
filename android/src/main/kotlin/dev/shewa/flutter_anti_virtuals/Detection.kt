package dev.shewa.flutter_anti_virtuals

/** Outcome of one check, converted to a map for the platform channel. */
internal data class Detection(
    val detected: Boolean,
    val supported: Boolean = true,
    val details: List<String> = emptyList()
) {
    fun toMap(): Map<String, Any> = mapOf(
        "detected" to detected,
        "supported" to supported,
        "details" to details
    )

    companion object {
        val unsupported = Detection(detected = false, supported = false)
        fun of(details: List<String>) = Detection(details.isNotEmpty(), details = details)
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

    fun isVirtualInterface(name: String): Boolean {
        val n = name.lowercase()
        // `ipsec*` is deliberately absent: Wi-Fi Calling / VoLTE keep those up.
        return n.startsWith("tun") || n.startsWith("ppp") || n.startsWith("tap") ||
            n.startsWith("wg") || n.startsWith("pptp")
    }
}
