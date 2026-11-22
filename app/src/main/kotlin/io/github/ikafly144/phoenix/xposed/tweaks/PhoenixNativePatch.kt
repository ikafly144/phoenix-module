package io.github.ikafly144.phoenix.xposed.tweaks

import android.content.pm.ApplicationInfo
import android.os.Build
import io.github.ikafly144.phoenix.Logger
import io.github.ikafly144.phoenix.xposed.*
import java.io.File
import java.util.zip.ZipFile

object PhoenixNative {
    @JvmStatic
    external fun nativeInit(
        cachePath: String,
        elfPath: String?,
        elfOffset: Long,
        elfSize: Long,
    ): Boolean

    @JvmStatic
    external fun nativeOnLibraryLoaded(): Boolean
}

/**
 * Loads `libphoenix.so` and applies the native patches to `liblibdiscord_wasm_host.so`:
 * 1. `2026-11-phoenix-app-access` / `2026-11-phoenix-rollout` (`client_access` evaluator -> `Some(true)`)
 * 2. `is_staff` (`flag_override = Some(STAFF)` -> `true`)
 */
val phoenixNativePatch by tweak {
    if (!loadModuleNativeLibrary(PhoenixConstants.NATIVE_LIB_NAME, modulePath, appInfo, log)) {
        log.e("Unable to load libphoenix.so; native Phoenix patches will not be applied")
        return@tweak
    }

    val cacheDir = File(appInfo.dataDir, PhoenixConstants.CACHE_DIR).apply { ensureDir() }
    val hostSource = resolveHostElfSource(appInfo, log)
    val modTime = File(modulePath).lastModified()

    val cacheKey = if (hostSource != null) {
        "${hostSource.sourceFile.lastModified()}_${hostSource.sourceFile.length()}_${hostSource.size}_$modTime"
    } else {
        "fallback_${File(appInfo.sourceDir).lastModified()}_$modTime"
    }
    val cacheFile = File(cacheDir, "patch_plan_${cacheKey.hashCode().toUInt().toString(16)}.bin")

    var tempExtracted: File? = null
    try {
        val elfPath: String?
        val elfOffset: Long
        val elfSize: Long

        if (cacheFile.isFile && cacheFile.length() > 0L) {
            // Fast path: cache file already exists, nativeInit will read it directly without touching the ELF.
            elfPath = hostSource?.takeIf { !it.needsExtraction }?.sourceFile?.absolutePath
            elfOffset = hostSource?.takeIf { !it.needsExtraction }?.offset ?: 0L
            elfSize = hostSource?.takeIf { !it.needsExtraction }?.size ?: 0L
        } else if (hostSource != null && hostSource.needsExtraction) {
            val tmp = File(cacheDir, "tmp_${PhoenixConstants.DISCORD_HOST_SO}")
            if (extractZipEntry(hostSource.sourceFile, hostSource.zipEntryName!!, tmp, log)) {
                tempExtracted = tmp
                elfPath = tmp.absolutePath
                elfOffset = 0L
                elfSize = tmp.length()
            } else {
                elfPath = null
                elfOffset = 0L
                elfSize = 0L
            }
        } else {
            elfPath = hostSource?.sourceFile?.absolutePath
            elfOffset = hostSource?.offset ?: 0L
            elfSize = hostSource?.size ?: 0L
        }

        val ready = PhoenixNative.nativeInit(
            cacheFile.absolutePath,
            elfPath,
            elfOffset,
            elfSize,
        )
        log.i("PhoenixNative initialized (planReady=$ready, cache=${cacheFile.name})")
    } finally {
        tempExtracted?.delete()
    }

    // Hook System.loadLibrary / Runtime.loadLibrary0 so we also trigger synchronously the instant
    // Discord loads liblibdiscord_wasm_host.so, before loadLibrary returns to the caller.
    hookLibraryLoad(log)
}

internal data class HostElfSource(
    val sourceFile: File,
    val offset: Long,
    val size: Long,
    val needsExtraction: Boolean,
    val zipEntryName: String? = null,
)

private fun resolveHostElfSource(appInfo: ApplicationInfo, log: Logger): HostElfSource? {
    appInfo.nativeLibraryDir?.let { dir ->
        val extracted = File(dir, PhoenixConstants.DISCORD_HOST_SO)
        if (extracted.isFile && extracted.length() > 0L) {
            log.i("Found extracted ${PhoenixConstants.DISCORD_HOST_SO} at ${extracted.absolutePath}")
            return HostElfSource(
                sourceFile = extracted,
                offset = 0L,
                size = extracted.length(),
                needsExtraction = false,
            )
        }
    }

    val apks = buildList {
        appInfo.splitSourceDirs?.forEach { add(File(it)) }
        add(File(appInfo.sourceDir))
    }

    for (abi in supportedTargetAbis()) {
        val entryName = "lib/$abi/${PhoenixConstants.DISCORD_HOST_SO}"
        for (apk in apks) {
            val loc = runCatching { ZipEntryLocator.locate(apk, entryName) }.getOrNull() ?: continue
            log.i("Found $entryName in ${apk.name} (stored=${loc.isStored}, offset=${loc.dataOffset}, size=${loc.uncompressedSize})")
            return HostElfSource(
                sourceFile = apk,
                offset = if (loc.isStored) loc.dataOffset else 0L,
                size = loc.uncompressedSize,
                needsExtraction = !loc.isStored,
                zipEntryName = entryName,
            )
        }
    }

    log.w("Could not locate ${PhoenixConstants.DISCORD_HOST_SO} in nativeLibraryDir or APKs (will fall back to dl_iterate_phdr)")
    return null
}

private fun hookLibraryLoad(log: Logger) {
    val onLoaded = { libName: String? ->
        if (libName != null && libName.contains("discord_wasm_host")) {
            val applied = PhoenixNative.nativeOnLibraryLoaded()
            log.i("Detected loadLibrary($libName) -> nativeOnLibraryLoaded=$applied")
        }
    }

    val hookedRuntime = runCatching {
        val method = Runtime::class.java.declaredMethods.firstOrNull {
            it.name == "loadLibrary0" && it.parameterTypes.size == 2 && it.parameterTypes[1] == String::class.java
        } ?: return@runCatching false

        method.isAccessible = true
        method.hook {
            after {
                onLoaded(args[1] as? String)
            }
        }
        true
    }.getOrDefault(false)

    if (!hookedRuntime) {
        runCatching {
            System::class.java.method("loadLibrary", String::class.java).hook {
                after {
                    onLoaded(args[0] as? String)
                }
            }
        }.onFailure { e ->
            log.w("Unable to hook System.loadLibrary; relying on native dl_iterate_phdr watcher", e)
        }
    }
}
