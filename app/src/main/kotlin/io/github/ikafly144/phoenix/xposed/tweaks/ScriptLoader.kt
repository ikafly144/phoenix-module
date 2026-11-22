package io.github.ikafly144.phoenix.xposed.tweaks

import android.content.res.AssetManager
import de.robv.android.xposed.XposedBridge
import io.github.ikafly144.phoenix.xposed.*
import java.lang.reflect.Method
import java.util.Collections
import java.util.WeakHashMap
import java.util.concurrent.CopyOnWriteArrayList

fun interface ScriptInjector {
    fun inject(scope: InjectorScope)
}

class InjectorScope internal constructor(
    private val tweak: Tweak,
    private val hookScope: HookScope,
    private val loadScriptFromFile: Method,
) {
    val tweakLog get() = tweak.log

    /**
     * Load a JS or Hermes bytecode file by absolute path before the host app's bundle.
     */
    fun runFile(absolutePath: String) {
        XposedBridge.invokeOriginalMethod(
            loadScriptFromFile,
            hookScope.thisObject,
            arrayOf(absolutePath, absolutePath, loadSynchronously),
        )
    }

    /** The `loadSynchronously` flag from the intercepted call. */
    val loadSynchronously: Any? get() = hookScope.args[2]
}

private val injectors = CopyOnWriteArrayList<ScriptInjector>()
private val injectedInstances = Collections.synchronizedSet(Collections.newSetFromMap(WeakHashMap<Any, Boolean>()))

/**
 * Register a [ScriptInjector] to be invoked by the [scriptLoader] tweak before the host app's bundle is loaded.
 */
fun registerScriptInjector(injector: ScriptInjector) {
    injectors += injector
}

/**
 * Hooks React Native's `JSBundleLoaderDelegate` script loading methods to run registered [ScriptInjector]s
 * before the host app's bundle loads (reused from RevengeXposed).
 */
val scriptLoader by tweak {
    val delegate = classLoader.loadClassOrNull("com.facebook.react.runtime.ReactInstance\$loadJSBundle\$1")
        ?: findBundleLoaderDelegate()
        ?: run {
            log.e("Unable to find the JSBundleLoaderDelegate used by ReactInstance")
            return@tweak
        }

    hookLoader(delegate)
}

private fun findBundleLoaderDelegate(): Class<*>? =
    DexFinder.findMethod {
        matcher {
            declaredClass { addInterface("com.facebook.react.bridge.JSBundleLoaderDelegate") }
            name("loadScriptFromFile")
            addInvoke { declaredClass("com.facebook.react.runtime.ReactInstance") }
        }
    }?.declaringClass

private fun Tweak.hookLoader(instance: Class<*>) {
    try {
        val loadScriptFromAssets = instance.method(
            "loadScriptFromAssets",
            AssetManager::class.java,
            String::class.java,
            Boolean::class.javaPrimitiveType,
        )

        val loadScriptFromFile = instance.method(
            "loadScriptFromFile",
            String::class.java,
            String::class.java,
            Boolean::class.javaPrimitiveType,
        )

        loadScriptFromAssets.hook {
            before {
                log.d("Intercepted loadScriptFromAssets: ${args[1]} (sync: ${args[2]})")
                runInjectorsOnce(this@hookLoader, loadScriptFromFile)
            }
        }

        loadScriptFromFile.hook {
            before {
                log.d("Intercepted loadScriptFromFile: ${args[0]} (sync: ${args[2]})")
                runInjectorsOnce(this@hookLoader, loadScriptFromFile)
            }
        }
    } catch (e: Exception) {
        log.e("Failed to hook script loading methods in ${instance.name}", e)
    }
}

private fun HookScope.runInjectorsOnce(
    tweak: Tweak,
    loadScriptFromFile: Method,
) {
    val target = thisObject ?: return
    if (!injectedInstances.add(target)) return

    val scope = InjectorScope(tweak, this, loadScriptFromFile)
    for (injector in injectors) {
        try {
            injector.inject(scope)
        } catch (e: Throwable) {
            tweak.log.e("ScriptInjector threw: ${injector::class.java.name}", e)
        }
    }
}
