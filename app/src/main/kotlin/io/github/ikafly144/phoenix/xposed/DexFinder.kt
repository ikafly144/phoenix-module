package io.github.ikafly144.phoenix.xposed

import android.content.pm.ApplicationInfo
import io.github.ikafly144.phoenix.logger
import kotlinx.serialization.Serializable
import org.luckypray.dexkit.DexKitBridge
import org.luckypray.dexkit.query.FindClass
import org.luckypray.dexkit.query.FindField
import org.luckypray.dexkit.query.FindMethod
import org.luckypray.dexkit.result.ClassData
import org.luckypray.dexkit.result.FieldData
import org.luckypray.dexkit.result.MethodData
import org.luckypray.dexkit.wrap.DexClass
import org.luckypray.dexkit.wrap.DexField
import org.luckypray.dexkit.wrap.DexMethod
import java.io.File
import java.lang.reflect.Field
import java.lang.reflect.Method

/**
 * Finds obfuscated host classes, methods, fields and values with DexKit (reused from RevengeXposed).
 *
 * Results are cached as descriptors per host APK and module build so later launches skip the scan.
 */
object DexFinder {
    private val log = logger("dexFinder")

    lateinit var classLoader: ClassLoader
        private set
    private lateinit var appInfo: ApplicationInfo
    private lateinit var modulePath: String
    private lateinit var cacheFile: File
    private lateinit var cache: Cache

    private var bridge: DexKitBridge? = null
    private var released = false
    private var nativeLoaded = false

    @Serializable
    private data class Cache(val key: String, val entries: MutableMap<String, String?> = mutableMapOf())

    @Synchronized
    fun init(appInfo: ApplicationInfo, classLoader: ClassLoader, modulePath: String) {
        this.appInfo = appInfo
        this.classLoader = classLoader
        this.modulePath = modulePath
        cacheFile = File(appInfo.dataDir, "${PhoenixConstants.CACHE_DIR}/dexkit.json")

        val apk = File(appInfo.sourceDir)
        val key = "${apk.lastModified()}:${apk.length()}:${File(modulePath).lastModified()}"
        cache = runCatching { PhoenixJson.decodeFromString(Cache.serializer(), cacheFile.readText()) }
            .getOrNull()
            ?.takeIf { it.key == key }
            ?: Cache(key)
    }

    @Synchronized
    fun <R : Any, T> findValue(
        key: String,
        encode: (R) -> String,
        decode: (String) -> T,
        query: DexKitBridge.() -> R?,
    ): T? = find(key, decode) { query()?.let(encode) }

    fun findClass(query: FindClass.() -> Unit): Class<*>? {
        val find = FindClass().apply(query)
        return findValue(
            "class:${find.hashKey()}",
            ClassData::descriptor,
            { DexClass(it).getInstance(classLoader) },
        ) { findClass(find).singleOrNull() }
    }

    fun findMethod(query: FindMethod.() -> Unit): Method? {
        val find = FindMethod().apply(query)
        return findValue(
            "method:${find.hashKey()}",
            MethodData::descriptor,
            { DexMethod(it).getMethodInstance(classLoader).apply { isAccessible = true } },
        ) { findMethod(find).singleOrNull() }
    }

    fun findField(query: FindField.() -> Unit): Field? {
        val find = FindField().apply(query)
        return findValue(
            "field:${find.hashKey()}",
            FieldData::descriptor,
            { DexField(it).getFieldInstance(classLoader).apply { isAccessible = true } },
        ) { findField(find).singleOrNull() }
    }

    @Synchronized
    fun release() {
        released = true
        bridge?.close()
        bridge = null
    }

    private fun <T> find(key: String, resolve: (String) -> T, query: DexKitBridge.() -> String?): T? {
        if (key in cache.entries) {
            val descriptor = cache.entries[key] ?: return null
            runCatching { return resolve(descriptor) }
                .onFailure { log.w("Cached result for $key no longer resolves: $descriptor", it) }
        }

        val bridge = openBridge() ?: return null
        val descriptor = try {
            val start = System.currentTimeMillis()
            bridge.query().also { log.i("Found $key in ${System.currentTimeMillis() - start}ms: $it") }
        } catch (e: Throwable) {
            log.e("Query for $key failed", e)
            return null
        } finally {
            if (released) closeBridge()
        }

        cache.entries[key] = descriptor
        saveCache()

        return descriptor?.let {
            runCatching { resolve(it) }
                .onFailure { e -> log.e("Unable to resolve $key: $it", e) }
                .getOrNull()
        }
    }

    private fun openBridge(): DexKitBridge? {
        bridge?.let { return it }

        return try {
            if (!nativeLoaded) {
                if (!loadModuleNativeLibrary("dexkit", modulePath, appInfo, log)) {
                    error("Failed to load libdexkit.so")
                }
                nativeLoaded = true
            }
            DexKitBridge.create(classLoader, true).also { bridge = it }
        } catch (e: Throwable) {
            log.e("Unable to start DexKit", e)
            null
        }
    }

    private fun closeBridge() {
        bridge?.close()
        bridge = null
    }

    private fun saveCache() {
        runCatching {
            cacheFile.parentFile?.ensureDir()
            val temp = File(cacheFile.path + ".tmp")
            temp.writeText(PhoenixJson.encodeToString(Cache.serializer(), cache))
            if (!temp.renameTo(cacheFile)) error("Unable to replace ${cacheFile.path}")
        }.onFailure { log.w("Unable to save the DexKit cache", it) }
    }
}
