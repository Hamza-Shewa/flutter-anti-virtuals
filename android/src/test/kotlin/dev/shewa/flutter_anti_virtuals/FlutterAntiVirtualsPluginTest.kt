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
    fun onlyRecentMockFixesCount() {
        assertTrue(Rules.isRecentFix(1_000))
        assertTrue(Rules.isRecentFix(Rules.MOCK_FIX_MAX_AGE_MS))
        assertFalse(Rules.isRecentFix(Rules.MOCK_FIX_MAX_AGE_MS + 1))
        assertFalse(Rules.isRecentFix(60 * 60 * 1000))
        assertTrue(Rules.isRecentFix(null))
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
            KnownPackages.virtualCamera + KnownPackages.cloners + KnownPackages.emulator
        assertEquals(known, queried)
    }
}

internal class EmulatorRulesTest {
    private val pixel = EmulatorEvidence(
        fingerprint = "google/husky/husky:15/AP4A.250105.002/12701944:user/release-keys",
        model = "Pixel 8 Pro",
        manufacturer = "Google",
        brand = "google",
        device = "husky",
        product = "husky",
        hardware = "husky",
        board = "husky",
        sensorNames = listOf("LSM6DSV Accelerometer", "LSM6DSV Gyroscope"),
        networkOperatorName = "Vodafone"
    )

    @Test
    fun realDevicesAreClean() {
        assertTrue(EmulatorRules.details(pixel).isEmpty())
        val samsung = pixel.copy(
            fingerprint = "samsung/a15nsxx/a15:14/UP1A.231005.007/A155FXXU1AXA1:user/release-keys",
            model = "SM-A155F", manufacturer = "samsung", brand = "samsung",
            device = "a15", product = "a15nsxx", hardware = "mt6789", board = "a15"
        )
        assertTrue(EmulatorRules.details(samsung).isEmpty())
        // Names that merely contain an emulator token.
        assertTrue(EmulatorRules.details(pixel.copy(product = "equinox", device = "lenovo_tab")).isEmpty())
    }

    @Test
    fun oneWeakIndicatorIsNotEnough() {
        assertTrue(EmulatorRules.details(pixel.copy(fingerprint = "generic/x/y:13/z:user/release-keys")).isEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(sensorNames = emptyList())).isEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(properties = mapOf("qemu.hw.mainkeys" to "0"))).isEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(networkOperatorName = "Android")).isEmpty())
    }

    @Test
    fun twoWeakIndicatorsAreEnough() {
        val d = EmulatorRules.details(
            pixel.copy(fingerprint = "generic/x/y:13/z:user/release-keys", sensorNames = emptyList())
        )
        assertEquals(listOf("generic fingerprint", "no sensors"), d)
    }

    @Test
    fun androidStudioEmulator() {
        val d = EmulatorRules.details(
            EmulatorEvidence(
                fingerprint = "google/sdk_gphone64_x86_64/emu64xa:16/BE2A.250530.026.F3/13894323:userdebug/dev-keys",
                model = "sdk_gphone64_x86_64",
                manufacturer = "Google",
                brand = "google",
                device = "emu64xa",
                product = "sdk_gphone64_x86_64",
                hardware = "ranchu",
                properties = mapOf("ro.kernel.qemu" to "1", "ro.boot.qemu" to "1", "ro.hardware" to "ranchu"),
                sensorNames = listOf("Goldfish 3-axis Accelerometer")
            )
        )
        assertTrue("ro.kernel.qemu=1" in d)
        assertTrue("emulator hardware ranchu" in d)
        assertTrue("1 emulated Goldfish sensors" in d)
    }

    @Test
    fun anyStrongIndicatorIsEnough() {
        assertTrue(EmulatorRules.details(pixel.copy(manufacturer = "Genymotion")).isNotEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(hardware = "vbox86")).isNotEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(product = "nox")).isNotEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(properties = mapOf("ro.boot.qemu" to "1"))).isNotEmpty())
        assertTrue(EmulatorRules.details(pixel.copy(properties = mapOf("ro.kernel.qemu" to "0"))).isEmpty())
        assertEquals(
            listOf("LDPlayer file /system/bin/ldinit"),
            EmulatorRules.details(pixel.copy(existingFiles = setOf("/system/bin/ldinit")))
        )
        assertEquals(
            listOf("emulator app com.bluestacks.home"),
            EmulatorRules.details(pixel.copy(installedPackages = setOf("com.bluestacks.home")))
        )
    }
}
