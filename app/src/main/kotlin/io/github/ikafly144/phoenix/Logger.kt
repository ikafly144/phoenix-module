package io.github.ikafly144.phoenix

import android.util.Log

/**
 * Namespaced [android.util.Log] facade. Create an instance via [logger].
 */
@Suppress("UNUSED")
class Logger(@PublishedApi internal val namespace: String?) {
    @PublishedApi
    internal fun fmt(msg: String): String = if (namespace != null) "$namespace - $msg" else msg

    inline fun v(t: Throwable? = null, msg: () -> String) = Log.v(TAG, fmt(msg()), t)
    inline fun d(t: Throwable? = null, msg: () -> String) = Log.d(TAG, fmt(msg()), t)
    inline fun i(t: Throwable? = null, msg: () -> String) = Log.i(TAG, fmt(msg()), t)
    inline fun w(t: Throwable? = null, msg: () -> String) = Log.w(TAG, fmt(msg()), t)
    inline fun e(t: Throwable? = null, msg: () -> String) = Log.e(TAG, fmt(msg()), t)

    fun v(msg: String, t: Throwable? = null) = Log.v(TAG, fmt(msg), t)
    fun d(msg: String, t: Throwable? = null) = Log.d(TAG, fmt(msg), t)
    fun i(msg: String, t: Throwable? = null) = Log.i(TAG, fmt(msg), t)
    fun w(msg: String, t: Throwable? = null) = Log.w(TAG, fmt(msg), t)
    fun e(msg: String, t: Throwable? = null) = Log.e(TAG, fmt(msg), t)

    companion object {
        const val TAG = "PhoenixModule"
    }
}

/** Returns a [Logger] tagged with [namespace]. */
fun logger(namespace: String): Logger = Logger(namespace)
