package io.github.ikafly144.phoenix.xposed.tweaks

import io.github.ikafly144.phoenix.xposed.PhoenixConstants
import io.github.ikafly144.phoenix.xposed.ensureDir
import io.github.ikafly144.phoenix.xposed.tweak
import java.io.File

/**
 * Enables Discord's Staff Settings (Developer Options & Experiment Overrides) in the React Native client
 * by injecting a preload script via [scriptLoader], reusing Revenge's `staff-settings` and Metro hook logic.
 */
val discordStaffSettings by tweak {
    val cacheDir = File(appInfo.dataDir, PhoenixConstants.CACHE_DIR).apply { ensureDir() }
    val preloadFile = File(cacheDir, "staff_settings_preload.js")

    runCatching {
        preloadFile.writeText(STAFF_SETTINGS_PRELOAD_JS)
    }.onFailure { e ->
        log.e("Failed to write staff_settings_preload.js", e)
        return@tweak
    }

    registerScriptInjector { scope ->
        scope.tweakLog.i("Injecting Discord Staff Settings (Experiment Overrides) preload script")
        scope.runFile(preloadFile.absolutePath)
    }
}

internal const val STAFF_SETTINGS_PRELOAD_JS = """
(function() {
    if (globalThis.__PHOENIX_STAFF_SETTINGS_PRELOAD__) return;
    globalThis.__PHOENIX_STAFF_SETTINGS_PRELOAD__ = true;

    var userStore = null;
    var devExpStore = null;
    var bypassingDefineProperties = false;

    var origDefineProperties = Object.defineProperties;
    var origDefineProperty = Object.defineProperty;

    function forceDeveloperDescriptor() {
        return {
            get: function() { return true; },
            set: function() {},
            configurable: true,
            enumerable: true
        };
    }

    Object.defineProperties = function(obj, props) {
        if (bypassingDefineProperties) return obj;
        if (props && typeof props === 'object' && 'isDeveloper' in props) {
            var copy = {};
            var keys = Object.keys(props);
            for (var i = 0; i < keys.length; i++) {
                var k = keys[i];
                copy[k] = (k === 'isDeveloper') ? forceDeveloperDescriptor() : props[k];
            }
            return origDefineProperties.call(Object, obj, copy);
        }
        return origDefineProperties.apply(Object, arguments);
    };

    Object.defineProperty = function(obj, prop, desc) {
        if (prop === 'isDeveloper' && desc && typeof desc === 'object') {
            return origDefineProperty.call(Object, obj, prop, forceDeveloperDescriptor());
        }
        return origDefineProperty.apply(Object, arguments);
    };

    function reinitDevExpStore(store) {
        if (!store) return;
        try {
            if (typeof store.initialize === 'function') {
                bypassingDefineProperties = true;
                try {
                    store.initialize();
                } finally {
                    bypassingDefineProperties = false;
                }
            }
            origDefineProperty.call(Object, store, 'isDeveloper', forceDeveloperDescriptor());
        } catch (_) {}
    }

    function patchUserStoreUtils(target) {
        if (!target || typeof target.isStaffEnv !== 'function') return;
        if (target.isStaffEnv.__phoenixPatched) return;

        var orig = target.isStaffEnv;
        var patched = function(user) {
            try {
                if (userStore && typeof userStore.getCurrentUser === 'function') {
                    var current = userStore.getCurrentUser();
                    if (current) return user === current;
                }
                if (user && typeof user === 'object') return true;
            } catch (_) {}
            return orig.apply(this, arguments);
        };
        patched.__phoenixPatched = true;
        try {
            target.isStaffEnv = patched;
        } catch (_) {
            try {
                origDefineProperty.call(Object, target, 'isStaffEnv', {
                    value: patched,
                    writable: true,
                    configurable: true,
                    enumerable: true
                });
            } catch (_2) {}
        }
        reinitDevExpStore(devExpStore);
    }

    function inspectStoreCandidate(candidate) {
        if (!candidate || typeof candidate !== 'object') return;
        try {
            if (typeof candidate.isStaffEnv === 'function') {
                patchUserStoreUtils(candidate);
            }
            var name = (typeof candidate.getName === 'function' && candidate.getName.length === 0)
                ? candidate.getName()
                : (candidate.constructor && candidate.constructor.displayName);
            if (name === 'UserStore') {
                userStore = candidate;
                reinitDevExpStore(devExpStore);
            } else if (name === 'DeveloperExperimentStore') {
                devExpStore = candidate;
                reinitDevExpStore(candidate);
            }
        } catch (_) {}
    }

    function inspectExports(exports) {
        if (!exports || (typeof exports !== 'object' && typeof exports !== 'function')) return;
        inspectStoreCandidate(exports);
        try {
            if (exports.default) inspectStoreCandidate(exports.default);
        } catch (_) {}
    }

    function wrapMetroDefine(defineFn) {
        if (typeof defineFn !== 'function' || defineFn.__phoenixWrapped) return defineFn;
        var wrapped = function(factory, moduleId, dependencyMap) {
            if (typeof factory === 'function' && !factory.__phoenixWrapped) {
                var origFactory = factory;
                var wrappedFactory = function(g, r, iD, iA, moduleObject, exports, deps) {
                    var res = origFactory.apply(this, arguments);
                    if (moduleObject && moduleObject.exports) {
                        inspectExports(moduleObject.exports);
                    }
                    return res;
                };
                wrappedFactory.__phoenixWrapped = true;
                return defineFn.call(this, wrappedFactory, moduleId, dependencyMap);
            }
            return defineFn.apply(this, arguments);
        };
        wrapped.__phoenixWrapped = true;
        return wrapped;
    }

    var currentDefine = globalThis.__d;
    if (typeof currentDefine === 'function') {
        currentDefine = wrapMetroDefine(currentDefine);
    }

    try {
        origDefineProperty.call(Object, globalThis, '__d', {
            configurable: true,
            enumerable: true,
            get: function() { return currentDefine; },
            set: function(fn) { currentDefine = wrapMetroDefine(fn); }
        });
    } catch (_) {}
})();
"""
