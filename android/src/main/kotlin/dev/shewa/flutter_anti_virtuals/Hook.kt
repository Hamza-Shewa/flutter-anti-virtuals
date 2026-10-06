package dev.shewa.flutter_anti_virtuals

import java.util.Locale

/** Everything the hook check looks at, collected on the device. */
internal data class HookEvidence(
    /** Lines of `/proc/self/maps`, or null when it could not be read. */
    val mapsLines: List<String>? = null,
    /** Names of this process's threads (`/proc/self/task/<tid>/comm`). */
    val threadNames: Set<String> = emptySet(),
    /** Classes from [HookRules.CLASSES] that can be loaded. */
    val loadedClasses: Set<String> = emptySet(),
    /** Class names in a stack trace taken inside the plugin. */
    val stackClassNames: List<String> = emptyList(),
    /** Packages from [KnownPackages.hooking] that are installed. */
    val installedPackages: Set<String> = emptySet(),
    /** Files from [HookRules.FILES] that exist. */
    val existingFiles: Set<String> = emptySet(),
    /** True when something accepts connections on the Frida server port. */
    val fridaPortOpen: Boolean = false,
    /** Paths the kernel finds but `java.io.File` reports missing (see [FileProbe]). */
    val hiddenPaths: Set<String> = emptySet()
)

/**
 * Pure classifier for instrumentation frameworks (Frida, Xposed/LSPosed/EdXposed, Substrate,
 * Riru/Zygisk modules), kept free of Android types so it can be unit tested. Every piece of
 * evidence is something a stock app process does not have, so any one is enough.
 *
 * A hook can remove this evidence (renamed gadget, hidden mappings, Zygisk DenyList), so a
 * clean result does not prove the app is not hooked.
 */
internal object HookRules {
    const val FRIDA_PORT = 27042

    /** Substrings of a mapped file path that identify a hooking library. */
    val MAP_TOKENS = listOf(
        "frida", "libgadget", "linjector", "xposed", "lsposed", "edxposed", "libsubstrate",
        "sandhook", "riru", "zygisk"
    )

    /** Thread names Frida's runtime creates inside the target process. */
    val THREAD_NAMES = listOf("gum-js-loop", "pool-frida", "frida")

    val CLASSES = listOf(
        "de.robv.android.xposed.XposedBridge",
        "de.robv.android.xposed.XC_MethodHook",
        "com.saurik.substrate.MS"
    )

    val FILES = listOf(
        "/system/framework/XposedBridge.jar",
        "/system/xposed.prop",
        "/system/lib/libsubstrate.so",
        "/system/lib64/libsubstrate.so",
        "/system/lib/libxposed_art.so",
        "/system/lib64/libxposed_art.so"
    )

    /** Package prefixes that show up in a stack trace when a method was hooked. */
    val STACK_TOKENS = listOf("de.robv.android.xposed", "com.saurik.substrate", "org.lsposed", "io.github.lsposed")

    fun details(e: HookEvidence): List<String> {
        val details = mutableListOf<String>()

        val paths = e.mapsLines.orEmpty().map { it.substringAfterLast(' ').trim().lowercase(Locale.ROOT) }
        MAP_TOKENS.filter { token -> paths.any { it.contains(token) } }
            .forEach { details += "hooking library $it in memory" }
        THREAD_NAMES.filter { it in e.threadNames }.forEach { details += "Frida thread $it" }
        e.loadedClasses.sorted().forEach { details += "hooking class $it" }
        STACK_TOKENS.filter { token -> e.stackClassNames.any { it.startsWith(token) } }
            .forEach { details += "hooked call stack through $it" }
        e.installedPackages.sorted().forEach { details += "hooking app $it" }
        e.existingFiles.sorted().forEach { details += "hooking file $it" }
        e.hiddenPaths.sorted().forEach { details += "file API hides $it" }
        if (e.fridaPortOpen) details += "Frida server port $FRIDA_PORT is open"

        return details.distinct()
    }
}

/** A debugger attached to the process. */
internal object DebuggerRules {
    /** `TracerPid:` of `/proc/self/status`: the pid of the tracing process, 0 when there is none. */
    fun tracerPid(status: String?): Int? =
        status?.lineSequence()
            ?.firstOrNull { it.startsWith("TracerPid:") }
            ?.substringAfter(':')?.trim()?.toIntOrNull()

    fun details(javaDebuggerConnected: Boolean, waitingForDebugger: Boolean, status: String?): List<String> {
        val details = mutableListOf<String>()
        if (javaDebuggerConnected) details += "Java debugger connected"
        if (waitingForDebugger) details += "waiting for a debugger"
        val tracer = tracerPid(status)
        if (tracer != null && tracer > 0) details += "process is traced by pid $tracer"
        return details
    }
}
