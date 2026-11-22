# Phoenix Module

An Xposed / LSPosed module for enabling **Discord Phoenix** on Android (`arm64-v8a` and `x86_64`).

## Features

1. **Discord Developer Mode & Experiment Overrides (React Native)**
   - Reuses [Revenge](https://github.com/revenge-mod/revenge-xposed)'s `DexFinder` (DexKit) and `ScriptLoader` to hook `JSBundleLoaderDelegate` and inject a lightweight preload script that enables `UserStoreUtils.isStaffEnv` and `DeveloperExperimentStore.isDeveloper`.
   - Unlocks **Staff Settings → Experiment Overrides** in the React Native Discord client so you can toggle Phoenix launch experiments directly from Settings.
2. **Native Phoenix Access & Staff Unlock (`liblibdiscord_wasm_host.so`)**
   - Dynamically locates targets via ELF64 anchors (port of [mantikafasi/phoenix-unlock](https://github.com/mantikafasi/phoenix-unlock)'s anchor resolution to C for `arm64-v8a` and `x86_64`, with per-APK offset caching):
     - **`2026-11-phoenix-app-access` / `2026-11-phoenix-rollout` (`client_access` evaluator)**: Patched in memory to return `Some(true)` so the `ClientAccessGate` ("No Access") screen is bypassed.
     - **`is_staff`**: Hooked in memory to set `flag_override = Some(STAFF)` on the shared store state and return `true`, enabling Staff Settings, DevTools, and Experiment Overrides inside Phoenix.

## Installation

1. Download the latest module APK from [Releases](https://github.com/ikafly144/phoenix-module/releases).
2. Install the APK on a device with LSPosed / Xposed (Android 8.0+).
3. Enable **Phoenix Module** for Discord (`com.discord`) in your Xposed manager.
4. Restart Discord, open **Settings → Staff Settings → Experiment Overrides**, and enable the Phoenix access/rollout experiments (`2026-11-phoenix-app-access` / `2026-11-phoenix-rollout`).

## Building

```bash
./gradlew :app:assembleDebug :app:assembleRelease :app:testDebugUnitTest
```

### Release Signing (GitHub Actions)

Set the following repository secrets to sign release builds in GitHub Actions:
- `KEYSTORE`: Base64-encoded JKS/PKCS12 keystore file
- `KEYSTORE_PASSWORD`: Keystore password
- `KEY_ALIAS`: Key alias
- `KEY_PASSWORD`: Key password

Pushing a tag matching `v*` (e.g., `v1.0.0`) automatically builds, tests, signs (if secrets are configured), and publishes a GitHub Release.

## Credits

- [mantikafasi/phoenix-unlock](https://github.com/mantikafasi/phoenix-unlock) — ELF anchor analysis and `client_access` / `is_staff` native patch design.
- [revenge-mod/revenge-xposed](https://github.com/revenge-mod/revenge-xposed) & [revenge-mod/revenge-bundle-next](https://github.com/revenge-mod/revenge-bundle-next) — `DexFinder`, `ScriptLoader`, and `staff-settings` implementation.
