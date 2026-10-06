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
            KnownPackages.virtualCamera + KnownPackages.cloners + KnownPackages.emulator +
            KnownPackages.root + KnownPackages.hooking
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

internal class RootRulesTest {
    private val stock = RootEvidence(
        tags = "release-keys",
        fingerprint = "google/husky/husky:15/AP4A.250105.002/12701944:user/release-keys",
        properties = mapOf(
            "ro.debuggable" to "0",
            "ro.secure" to "1",
            "ro.build.type" to "user",
            "ro.build.tags" to "release-keys",
            "ro.boot.verifiedbootstate" to "green",
            "ro.boot.flash.locked" to "1",
            "ro.boot.vbmeta.device_state" to "locked"
        ),
        mounts = listOf(
            "/dev/block/dm-0 /system ext4 ro,seclabel,relatime 0 0",
            "/dev/block/dm-1 /vendor ext4 ro,seclabel,relatime 0 0",
            "/dev/block/dm-5 /data f2fs rw,lazytime,seclabel,nosuid,nodev 0 0",
            "tmpfs /apex tmpfs rw,seclabel,nosuid,nodev,noexec,relatime,mode=755 0 0"
        )
    )

    @Test
    fun stockDeviceIsClean() {
        assertTrue(RootRules.details(stock).isEmpty())
        assertTrue(RootRules.details(RootEvidence()).isEmpty())
    }

    @Test
    fun oneWeakIndicatorIsNotEnough() {
        assertTrue(RootRules.details(stock.copy(tags = "test-keys")).isEmpty())
        assertTrue(
            RootRules.details(stock.copy(properties = stock.properties + ("ro.boot.verifiedbootstate" to "orange")))
                .isEmpty()
        )
    }

    @Test
    fun theSignsOfADebugBuildCountOnce() {
        val debug = stock.copy(
            tags = "dev-keys",
            properties = stock.properties + mapOf("ro.debuggable" to "1", "ro.build.type" to "userdebug")
        )
        assertTrue(RootRules.details(debug).isEmpty())
    }

    @Test
    fun aDebugBuildWithAnUnlockedBootloaderIsReported() {
        val d = RootRules.details(
            stock.copy(
                tags = "test-keys",
                properties = stock.properties + ("ro.boot.flash.locked" to "0")
            )
        )
        assertEquals(listOf("debug build of the system", "unlocked bootloader"), d)
    }

    @Test
    fun strongIndicatorsAreEnoughOnTheirOwn() {
        assertEquals(
            listOf("root binary /system/xbin/su"),
            RootRules.details(stock.copy(binaries = setOf("/system/xbin/su")))
        )
        assertEquals(
            listOf("root app com.topjohnwu.magisk"),
            RootRules.details(stock.copy(installedPackages = setOf("com.topjohnwu.magisk")))
        )
        assertEquals(
            listOf("root file /system/app/Superuser.apk"),
            RootRules.details(stock.copy(existingFiles = setOf("/system/app/Superuser.apk")))
        )
        assertEquals(
            listOf("adbd runs as root"),
            RootRules.details(stock.copy(properties = stock.properties + ("service.adb.root" to "1")))
        )
        assertEquals(
            listOf("ro.secure=0"),
            RootRules.details(stock.copy(properties = stock.properties + ("ro.secure" to "0")))
        )
        assertEquals(listOf("SELinux is permissive"), RootRules.details(stock.copy(selinuxEnforce = "0\n")))
        assertTrue(RootRules.details(stock.copy(selinuxEnforce = "1")).isEmpty())
    }

    @Test
    fun aWritableSystemPartitionIsReported() {
        val d = RootRules.details(
            stock.copy(mounts = listOf("/dev/block/dm-0 /system ext4 rw,seclabel,relatime 0 0"))
        )
        assertEquals(listOf("writable /system"), d)
        // /data is writable on every device.
        assertTrue(RootRules.details(stock.copy(mounts = listOf("/dev/x /data f2fs rw,seclabel 0 0"))).isEmpty())
        // "ro" listed after other options does not make it read-write.
        assertTrue(
            RootRules.details(stock.copy(mounts = listOf("/dev/x /system ext4 ro,rw_foo 0 0"))).isEmpty()
        )
    }

    @Test
    fun magiskAndKernelSuMountsAreReported() {
        assertEquals(
            listOf("magisk mount /system/bin"),
            RootRules.details(stock.copy(mounts = listOf("magisk /system/bin tmpfs ro 0 0")))
        )
        assertEquals(
            listOf("ksu mount /system"),
            RootRules.details(stock.copy(mounts = listOf("KSU /system overlay ro,seclabel 0 0")))
        )
        assertEquals(
            listOf("magisk mount /sbin/.magisk/mirror/system"),
            RootRules.details(stock.copy(mounts = listOf("/dev/x /sbin/.magisk/mirror/system ext4 ro 0 0")))
        )
        // An unrelated name that merely contains the letters.
        assertTrue(RootRules.details(stock.copy(mounts = listOf("/dev/x /mnt/ksulu ext4 ro 0 0"))).isEmpty())
    }

    @Test
    fun malformedMountLinesAreIgnored() {
        assertTrue(RootRules.details(stock.copy(mounts = listOf("", "garbage", "a b"))).isEmpty())
    }
}

internal class HookRulesTest {
    private val clean = HookEvidence(
        mapsLines = listOf(
            "7f1c000000-7f1c021000 r-xp 00000000 fd:01 1234 /system/lib64/libc.so",
            "7f1d000000-7f1d100000 r-xp 00000000 fd:01 5678 /data/app/~~x/dev.shewa.app-1/lib/arm64/libflutter.so",
            "7f1e000000-7f1e001000 rw-p 00000000 00:00 0 [anon:libc_malloc]"
        ),
        threadNames = setOf("main", "RenderThread", "1.ui", "1.raster")
    )

    @Test
    fun cleanProcessIsClean() {
        assertTrue(HookRules.details(clean).isEmpty())
        assertTrue(HookRules.details(HookEvidence()).isEmpty())
    }

    @Test
    fun hookingLibrariesInMemoryAreReported() {
        val d = HookRules.details(
            clean.copy(
                mapsLines = clean.mapsLines.orEmpty() + listOf(
                    "7f2000000-7f2100000 r-xp 0 fd:01 9 /data/local/tmp/re.frida.server/frida-agent-64.so",
                    "7f3000000-7f3100000 r-xp 0 fd:01 9 /data/adb/lspd/framework/liblspd.so",
                    "7f4000000-7f4100000 r-xp 0 fd:01 9 /data/data/x/libgadget.so"
                )
            )
        )
        assertEquals(
            listOf("hooking library frida in memory", "hooking library libgadget in memory"),
            d.filter { it.contains("frida") || it.contains("libgadget") }
        )
    }

    @Test
    fun fridaThreadsClassesPackagesFilesAndPort() {
        assertEquals(
            listOf("Frida thread gum-js-loop"),
            HookRules.details(clean.copy(threadNames = clean.threadNames + "gum-js-loop"))
        )
        assertEquals(
            listOf("hooking class de.robv.android.xposed.XposedBridge"),
            HookRules.details(clean.copy(loadedClasses = setOf("de.robv.android.xposed.XposedBridge")))
        )
        assertEquals(
            listOf("hooking app org.lsposed.manager"),
            HookRules.details(clean.copy(installedPackages = setOf("org.lsposed.manager")))
        )
        assertEquals(
            listOf("hooking file /system/xposed.prop"),
            HookRules.details(clean.copy(existingFiles = setOf("/system/xposed.prop")))
        )
        assertEquals(
            listOf("Frida server port 27042 is open"),
            HookRules.details(clean.copy(fridaPortOpen = true))
        )
    }

    @Test
    fun aHookedCallShowsInTheStack() {
        val d = HookRules.details(
            clean.copy(
                stackClassNames = listOf(
                    "dev.shewa.flutter_anti_virtuals.AntiVirtualScanner",
                    "de.robv.android.xposed.XposedBridge",
                    "org.lsposed.lspd.hooker.HandleHookedMethod"
                )
            )
        )
        assertEquals(
            listOf(
                "hooked call stack through de.robv.android.xposed",
                "hooked call stack through org.lsposed"
            ),
            d
        )
        assertTrue(
            HookRules.details(clean.copy(stackClassNames = listOf("dev.shewa.flutter_anti_virtuals.X"))).isEmpty()
        )
    }
}

internal class DebuggerRulesTest {
    private val status = "Name:\tapp\nTracerPid:\t0\nUid:\t10234\n"

    @Test
    fun noDebugger() {
        assertTrue(DebuggerRules.details(false, false, status).isEmpty())
        assertTrue(DebuggerRules.details(false, false, null).isEmpty())
        assertEquals(0, DebuggerRules.tracerPid(status))
    }

    @Test
    fun debuggersAreReported() {
        assertEquals(listOf("Java debugger connected"), DebuggerRules.details(true, false, status))
        assertEquals(listOf("waiting for a debugger"), DebuggerRules.details(false, true, status))
        assertEquals(
            listOf("process is traced by pid 4321"),
            DebuggerRules.details(false, false, "Name:\tapp\nTracerPid:\t4321\n")
        )
    }

    @Test
    fun unreadableStatusIsNotADebugger() {
        assertEquals(null, DebuggerRules.tracerPid("garbage"))
        assertTrue(DebuggerRules.details(false, false, "TracerPid:\tx\n").isEmpty())
    }
}
