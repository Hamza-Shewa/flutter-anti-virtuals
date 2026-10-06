package dev.shewa.flutter_anti_virtuals

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

internal class NetworkSignatureTest {
    private val wifi = NetworkState("100", vpn = false, proxy = null)
    private val vpn = NetworkState("101", vpn = true, proxy = null)

    @Test
    fun orderDoesNotMatter() {
        assertEquals(
            NetworkSignature.of(listOf(wifi, vpn), null),
            NetworkSignature.of(listOf(vpn, wifi), null),
        )
    }

    @Test
    fun aVpnOrProxyChangesTheSignature() {
        val base = NetworkSignature.of(listOf(wifi), null)
        assertFalse(base == NetworkSignature.of(listOf(wifi, vpn), null))
        assertFalse(base == NetworkSignature.of(listOf(wifi.copy(proxy = "10.0.0.1:8080")), null))
        assertFalse(base == NetworkSignature.of(listOf(wifi), "10.0.0.1:8080"))
        assertFalse(base == NetworkSignature.of(emptyList(), null))
    }
}

internal class RulesTest {
    @Test
    fun clockFlagsAutoTimeOffAndSkew() {
        val d = Rules.clockDetails(false, true, deviceMs = 10_000, trustedMs = 0, maxSkewMs = 5_000)
        assertEquals(2, d.size)
        assertTrue(Rules.clockDetails(true, true, 1_000, 0, 5_000).isEmpty())
        assertTrue(Rules.clockDetails(null, null, 1_000, null, 5_000).isEmpty())
    }

    @Test
    fun signatureComparisonIgnoresCaseAndColons() {
        assertTrue(Rules.signatureMatches(listOf("ABCD12"), listOf("ab:cd:12")))
        assertFalse(Rules.signatureMatches(listOf("ffff"), listOf("abcd")))
    }

    @Test
    fun installerMustBeTrusted() {
        val trusted = listOf("com.android.vending")
        assertFalse(Rules.isUntrustedInstaller("com.android.vending", trusted))
        assertTrue(Rules.isUntrustedInstaller("com.evil.store", trusted))
        assertTrue(Rules.isUntrustedInstaller(null, trusted))
    }

    @Test
    fun clonedDataDirDetection() {
        assertFalse(Rules.isClonedDataDir("/data/user/0/a.b", "a.b", 0))
        assertFalse(Rules.isClonedDataDir("/data/user/10/a.b/", "a.b", 10))
        assertFalse(Rules.isClonedDataDir("/mnt/expand/1234-abcd/user/0/a.b", "a.b", 0))
        assertTrue(Rules.isClonedDataDir("/mnt/expand/1234-abcd/user/0/other.pkg", "a.b", 0))
        assertTrue(Rules.isClonedDataDir("/data/data/com.parallel/virtual/data/user/0/a.b", "a.b", 0))
    }

    @Test
    fun virtualInterfaces() {
        assertTrue(Rules.isVirtualInterface("tun0"))
        assertTrue(Rules.isVirtualInterface("wg0"))
        assertFalse(Rules.isVirtualInterface("wlan0"))
        assertFalse(Rules.isVirtualInterface("ipsec0"))
    }

    @Test
    fun manifestQueriesMatchKnownPackages() {
        val manifest = java.io.File("src/main/AndroidManifest.xml").readText()
        val queried = Regex("<package android:name=\"([^\"]+)\"").findAll(manifest)
            .map { it.groupValues[1] }.toSet()
        val known = KnownPackages.mockLocation + KnownPackages.remoteControl +
            KnownPackages.virtualCamera + KnownPackages.cloners
        assertEquals(known, queried)
    }
}
