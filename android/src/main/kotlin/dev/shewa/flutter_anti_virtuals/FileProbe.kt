package dev.shewa.flutter_anti_virtuals

import android.system.Os
import java.io.File

/**
 * Looks for a path through two independent layers: `java.io.File`, which is what root-hiding
 * modules and Frida scripts patch, and `Os.stat`, a direct system call that those patches
 * normally miss. A path counts as present when either layer finds it, and a path only the kernel
 * finds is evidence that the file API was tampered with (see [HookEvidence.hiddenPaths]).
 */
internal object FileProbe {
    fun javaExists(path: String): Boolean = try { File(path).exists() } catch (_: Throwable) { false }

    fun kernelExists(path: String): Boolean = try {
        Os.stat(path)
        true
    } catch (_: Throwable) {
        false
    }

    fun exists(path: String): Boolean = javaExists(path) || kernelExists(path)

    /** Paths among [paths] that the kernel finds but `java.io.File` does not. */
    fun hidden(paths: Collection<String>): Set<String> =
        paths.filter { !javaExists(it) && kernelExists(it) }.toSet()
}
