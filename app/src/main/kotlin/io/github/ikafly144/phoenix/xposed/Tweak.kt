package io.github.ikafly144.phoenix.xposed

import android.content.pm.ApplicationInfo
import io.github.ikafly144.phoenix.Logger
import io.github.ikafly144.phoenix.logger
import kotlin.properties.PropertyDelegateProvider
import kotlin.properties.ReadOnlyProperty

interface HostScope {
    val modulePath: String
    val appInfo: ApplicationInfo
    val classLoader: ClassLoader
    val dexFinder: DexFinder
}

class Tweak internal constructor(
    val name: String,
    context: HostScope,
) : HostScope by context {
    val log: Logger = logger(name)
}

class TweakSpec internal constructor(
    val name: String,
    private val body: Tweak.() -> Unit,
) {
    fun applyTo(context: HostScope) {
        val tweak = Tweak(name, context)
        try {
            tweak.body()
        } catch (e: Throwable) {
            tweak.log.e("Tweak '$name' failed to apply", e)
        }
    }
}

fun tweak(
    body: Tweak.() -> Unit,
): PropertyDelegateProvider<Any?, ReadOnlyProperty<Any?, TweakSpec>> =
    PropertyDelegateProvider { _, property ->
        val spec = TweakSpec(property.name, body)
        ReadOnlyProperty { _, _ -> spec }
    }
