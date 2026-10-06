package dev.shewa.flutter_anti_virtuals

import java.util.Locale

/** Everything the emulator check looks at, collected on the device. */
internal data class EmulatorEvidence(
    val fingerprint: String = "",
    val model: String = "",
    val manufacturer: String = "",
    val brand: String = "",
    val device: String = "",
    val product: String = "",
    val hardware: String = "",
    val board: String = "",
    /** System properties, see [EmulatorRules.PROPERTIES]. */
    val properties: Map<String, String> = emptyMap(),
    /** Paths from [EmulatorRules.FILES] that exist. */
    val existingFiles: Set<String> = emptySet(),
    /** Packages from [KnownPackages.emulator] that are installed. */
    val installedPackages: Set<String> = emptySet(),
    /** Names of the device's sensors, or null when they could not be read. */
    val sensorNames: List<String>? = null,
    val networkOperatorName: String? = null
)

/**
 * Pure emulator classifier, kept free of Android types so it can be unit tested.
 *
 * Real devices must never be reported, so evidence is split in two. A strong indicator is
 * something no retail device has (qemu properties, the goldfish/ranchu hardware, emulator
 * device files, emulator vendor apps) and is enough on its own. A weak indicator (a "generic"
 * fingerprint, an SDK product name, no sensors, ...) also shows up on some cheap or custom-ROM
 * devices, so at least [WEAK_THRESHOLD] of them are needed.
 */
internal object EmulatorRules {
    const val WEAK_THRESHOLD = 2

    val PROPERTIES = listOf(
        "ro.kernel.qemu",
        "ro.boot.qemu",
        "ro.hardware",
        "ro.boot.hardware",
        "ro.genymotion.version",
        "ro.genyd.caps.baseband",
        "init.svc.qemud",
        "init.svc.qemu-props",
        "init.svc.goldfish-logcat",
        "init.svc.goldfish-setup",
        "qemu.hw.mainkeys",
        "qemu.sf.fake_camera",
        "ro.bluestacks.version",
        "ro.noxpatch",
        "ro.memu.version"
    )

    /** Files only present on emulators, with the product they belong to. */
    val FILES = mapOf(
        "/dev/qemu_pipe" to "qemu",
        "/dev/goldfish_pipe" to "qemu",
        "/dev/socket/qemud" to "qemu",
        "/system/bin/qemu-props" to "qemu",
        "/system/lib/libc_malloc_debug_qemu.so" to "qemu",
        "/sys/qemu_trace" to "qemu",
        "/dev/socket/genyd" to "Genymotion",
        "/dev/socket/baseband_genyd" to "Genymotion",
        "/system/bin/androVM-prop" to "Genymotion",
        "/system/bin/nox-prop" to "Nox",
        "/system/bin/nox-vbox-sf" to "Nox",
        "/system/lib/libnoxspeedup.so" to "Nox",
        "/system/lib/libnoxd.so" to "Nox",
        "/fstab.nox" to "Nox",
        "/init.nox.rc" to "Nox",
        "/ueventd.nox.rc" to "Nox",
        "/system/bin/ldinit" to "LDPlayer",
        "/system/bin/ldmountsf" to "LDPlayer",
        "/system/lib/libldutils.so" to "LDPlayer",
        "/system/bin/microvirtd" to "MEmu",
        "/system/bin/microvirt-prop" to "MEmu",
        "/data/.bluestacks.prop" to "BlueStacks",
        "/system/bin/bstfolderd" to "BlueStacks",
        "/mnt/windows/BstSharedFolder" to "BlueStacks",
        "/fstab.vbox86" to "VirtualBox",
        "/init.vbox86.rc" to "VirtualBox",
        "/ueventd.vbox86.rc" to "VirtualBox",
        "/fstab.ranchu" to "qemu",
        "/init.ranchu.rc" to "qemu",
        "/ueventd.ranchu.rc" to "qemu",
        "/fstab.goldfish" to "qemu",
        "/init.goldfish.rc" to "qemu",
        "/ueventd.goldfish.rc" to "qemu"
    )

    /** Emulator hardware names (`Build.HARDWARE`, `ro.hardware`). */
    private val emulatorHardware = listOf("goldfish", "ranchu", "vbox86", "ttvm_x86", "nox", "andy")

    /** Emulator vendors that name themselves in the build identity. */
    private val vendorTokens = listOf("genymotion", "bluestacks", "microvirt", "ldplayer", "androvm")

    fun details(e: EmulatorEvidence): List<String> {
        val strong = mutableListOf<String>()
        val weak = mutableListOf<String>()

        val fingerprint = e.fingerprint.norm()
        val model = e.model.norm()
        val manufacturer = e.manufacturer.norm()
        val brand = e.brand.norm()
        val device = e.device.norm()
        val product = e.product.norm()
        val hardware = e.hardware.norm()
        val props = e.properties.mapValues { it.value.norm() }

        // ---- strong ----
        if (props["ro.kernel.qemu"] == "1") strong += "ro.kernel.qemu=1"
        if (props["ro.boot.qemu"] == "1") strong += "ro.boot.qemu=1"
        for (hw in listOf(hardware, props["ro.hardware"].orEmpty(), props["ro.boot.hardware"].orEmpty()).distinct()) {
            if (hw.isNotEmpty() && emulatorHardware.any { hw == it || hw.startsWith(it) }) {
                strong += "emulator hardware $hw"
            }
        }
        for (key in listOf(
            "ro.genymotion.version", "ro.genyd.caps.baseband", "init.svc.qemud",
            "init.svc.qemu-props", "init.svc.goldfish-logcat", "init.svc.goldfish-setup",
            "qemu.sf.fake_camera", "ro.bluestacks.version", "ro.noxpatch", "ro.memu.version"
        )) {
            if (!props[key].isNullOrEmpty()) strong += "emulator property $key"
        }
        val identity = listOf(fingerprint, model, manufacturer, brand, device, product, hardware)
        vendorTokens.filter { token -> identity.any { it.contains(token) } }
            .forEach { strong += "emulator vendor $it in build identity" }
        // `contains` would match unrelated names (equinox), so Nox and MEmu need exact prefixes.
        if (listOf(product, device, model).any { it.startsWith("nox") }) strong += "Nox build identity"
        if (listOf(product, device, model, brand).any { it == "memu" || it.startsWith("memu ") }) {
            strong += "MEmu build identity"
        }
        e.existingFiles.sorted().forEach { path ->
            strong += "${FILES[path] ?: "emulator"} file $path"
        }
        e.installedPackages.sorted().forEach { strong += "emulator app $it" }
        val goldfishSensors = e.sensorNames.orEmpty().count { it.norm().contains("goldfish") }
        if (goldfishSensors > 0) strong += "$goldfishSensors emulated Goldfish sensors"

        // ---- weak ----
        if (fingerprint.startsWith("generic") || fingerprint.startsWith("unknown")) {
            weak += "generic fingerprint"
        }
        if (fingerprint.contains("/sdk_gphone") || fingerprint.contains(":sdk_gphone") ||
            fingerprint.contains("emulator") || fingerprint.contains("/vbox86p")
        ) weak += "emulator fingerprint"
        if (listOf("google_sdk", "emulator", "android sdk built for", "sdk_gphone").any { model.contains(it) }) {
            weak += "emulator model ${e.model}"
        }
        if (product == "sdk" || product == "google_sdk" || product.startsWith("sdk_") ||
            product.contains("_sdk_") || product.endsWith("_sdk") ||
            product.contains("emulator") || product.contains("simulator") || product.contains("vbox86p")
        ) weak += "emulator product ${e.product}"
        if (brand.startsWith("generic") && device.startsWith("generic")) weak += "generic brand and device"
        if (e.board.norm() == "goldfish" || e.board.norm().startsWith("goldfish_")) weak += "goldfish board"
        // Some custom ROMs set this one to toggle the navigation bar.
        if (!props["qemu.hw.mainkeys"].isNullOrEmpty()) weak += "qemu.hw.mainkeys set"
        if (e.sensorNames != null && e.sensorNames.isEmpty()) weak += "no sensors"
        if (e.networkOperatorName?.norm() == "android") weak += "network operator \"Android\""

        val detected = strong.isNotEmpty() || weak.size >= WEAK_THRESHOLD
        return if (detected) (strong + weak).distinct() else emptyList()
    }

    private fun String.norm(): String = trim().lowercase(Locale.ROOT)
}
