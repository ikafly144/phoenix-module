#define _GNU_SOURCE
#include "phoenix_elf.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define TAG "PhoenixModule"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static phoenix_patch_plan_t g_plan;
static int g_has_plan = 0;
static int g_patched = 0;
static int g_watcher_started = 0;
static char g_cache_path[512] = {0};

static int load_plan_from_cache(const char *path, phoenix_patch_plan_t *out) {
    if (!path || !path[0]) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;

    phoenix_patch_plan_t tmp;
    ssize_t n = read(fd, &tmp, sizeof(tmp));
    close(fd);
    if (n != (ssize_t)sizeof(tmp)) return -1;
    if (tmp.magic != PHOENIX_PLAN_MAGIC || tmp.version != PHOENIX_PLAN_VERSION) return -1;
    if (tmp.access_len == 0 || tmp.access_len > PHOENIX_MAX_CODE_LEN) return -1;
    if (tmp.staff_len == 0 || tmp.staff_len > PHOENIX_MAX_CODE_LEN) return -1;

    *out = tmp;
    return 0;
}

static void save_plan_to_cache(const char *path, const phoenix_patch_plan_t *plan) {
    if (!path || !path[0]) return;
    char tmp_path[540];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return;

    ssize_t written = write(fd, plan, sizeof(*plan));
    close(fd);
    if (written == (ssize_t)sizeof(*plan)) {
        rename(tmp_path, path);
    } else {
        unlink(tmp_path);
    }
}

static int resolve_plan_from_file_range(
    const char *path,
    int64_t offset,
    int64_t size,
    phoenix_patch_plan_t *out
) {
    if (!path || !path[0] || offset < 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOGE("open(%s) failed: %s", path, strerror(errno));
        return -1;
    }

    if (size <= 0) {
        struct stat st;
        if (fstat(fd, &st) != 0 || st.st_size <= offset) {
            close(fd);
            return -1;
        }
        size = st.st_size - offset;
    }

    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) ps = 4096;
    int64_t aligned_off = offset & ~((int64_t)ps - 1);
    size_t delta = (size_t)(offset - aligned_off);
    size_t map_len = (size_t)size + delta;

    void *map = mmap(NULL, map_len, PROT_READ, MAP_PRIVATE, fd, (off_t)aligned_off);
    close(fd);
    if (map == MAP_FAILED) {
        LOGE("mmap(%s, off=%lld, len=%lld) failed: %s",
             path, (long long)offset, (long long)size, strerror(errno));
        return -1;
    }

    char err[256] = {0};
    int rc = phoenix_resolve_elf((const uint8_t *)map + delta, (size_t)size, out, err, sizeof(err));
    munmap(map, map_len);

    if (rc != 0) {
        LOGE("phoenix_resolve_elf(%s) failed: %s", path, err);
        return -1;
    }

    LOGI("resolved ELF (%s): access=0x%llx (%u bytes), is_staff=0x%llx (%u bytes, tag=+0x%x, val=+0x%x)",
         path,
         (unsigned long long)out->access_va, out->access_len,
         (unsigned long long)out->staff_va, out->staff_len,
         out->staff_tag_off, out->staff_val_off);
    return 0;
}

static int write_code(
    const char *name,
    uint8_t *t,
    const uint8_t *expect,
    size_t elen,
    const uint8_t *code,
    size_t clen
) {
    if (memcmp(t, code, clen) == 0) {
        LOGI("patch %s: already applied at %p", name, (void *)t);
        return 0;
    }
    if (elen > 0 && memcmp(t, expect, elen) != 0) {
        LOGE("patch %s: unexpected prologue bytes at %p, skipped", name, (void *)t);
        return -1;
    }

    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    if (ps == 0) ps = 4096;
    uintptr_t page = (uintptr_t)t & ~(ps - 1);
    size_t span = (((uintptr_t)t + clen - page) + ps - 1) & ~(ps - 1);
    if (span < ps * 2) span = ps * 2;

    if (mprotect((void *)page, span, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        LOGE("patch %s: mprotect failed at %p: %s", name, (void *)page, strerror(errno));
        return -1;
    }
    memcpy(t, code, clen);
    __builtin___clear_cache((char *)t, (char *)t + clen);
    mprotect((void *)page, span, PROT_READ | PROT_EXEC);
    LOGI("patch %s: applied at %p (%zu bytes)", name, (void *)t, clen);
    return 0;
}

typedef struct {
    uintptr_t base;
    char      name[512];
} dl_match_t;

static int find_host_lib_cb(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    if (info->dlpi_name && strstr(info->dlpi_name, "liblibdiscord_wasm_host.so")) {
        dl_match_t *m = (dl_match_t *)data;
        m->base = (uintptr_t)info->dlpi_addr;
        snprintf(m->name, sizeof(m->name), "%s", info->dlpi_name);
        return 1;
    }
    return 0;
}

static int try_apply_patch_locked(void) {
    if (g_patched) return 1;

    dl_match_t m;
    memset(&m, 0, sizeof(m));
    dl_iterate_phdr(find_host_lib_cb, &m);
    if (!m.base) return 0;

    if (!g_has_plan && m.name[0] && !strstr(m.name, "!/")) {
        if (resolve_plan_from_file_range(m.name, 0, 0, &g_plan) == 0) {
            g_has_plan = 1;
            save_plan_to_cache(g_cache_path, &g_plan);
        }
    }

    if (!g_has_plan) {
        LOGE("liblibdiscord_wasm_host.so loaded at %p, but patch plan is unavailable", (void *)m.base);
        return 0;
    }

    uint8_t *base = (uint8_t *)m.base;
    int rc1 = write_code(
        "access",
        base + g_plan.access_va,
        g_plan.access_expect,
        g_plan.access_exp_len,
        g_plan.access_code,
        g_plan.access_len
    );
    int rc2 = write_code(
        "is_staff",
        base + g_plan.staff_va,
        g_plan.staff_expect,
        g_plan.staff_exp_len,
        g_plan.staff_code,
        g_plan.staff_len
    );

    if (rc1 == 0 && rc2 == 0) {
        g_patched = 1;
        LOGI("all Phoenix native patches applied (base=%p)", (void *)base);
        return 1;
    }
    return 0;
}

static void *watcher_thread(void *unused) {
    (void)unused;
    for (int i = 0; i < 60000; i++) {
        pthread_mutex_lock(&g_mutex);
        int done = g_patched || try_apply_patch_locked();
        pthread_mutex_unlock(&g_mutex);
        if (done) return NULL;
        usleep(2000);
    }
    LOGI("watcher finished without liblibdiscord_wasm_host.so loading (normal if running React Native client)");
    return NULL;
}

JNIEXPORT jboolean JNICALL
Java_io_github_ikafly144_phoenix_xposed_tweaks_PhoenixNative_nativeInit(
    JNIEnv *env,
    jclass clazz,
    jstring jCachePath,
    jstring jElfPath,
    jlong elfOffset,
    jlong elfSize
) {
    (void)clazz;
    const char *cache_path = jCachePath ? (*env)->GetStringUTFChars(env, jCachePath, NULL) : NULL;
    const char *elf_path = jElfPath ? (*env)->GetStringUTFChars(env, jElfPath, NULL) : NULL;

    pthread_mutex_lock(&g_mutex);

    if (cache_path) {
        snprintf(g_cache_path, sizeof(g_cache_path), "%s", cache_path);
    }

    if (!g_has_plan && cache_path && load_plan_from_cache(cache_path, &g_plan) == 0) {
        g_has_plan = 1;
        LOGI("loaded patch plan from cache: access=0x%llx, is_staff=0x%llx",
             (unsigned long long)g_plan.access_va, (unsigned long long)g_plan.staff_va);
    }

    if (!g_has_plan && elf_path && elf_path[0]) {
        if (resolve_plan_from_file_range(elf_path, (int64_t)elfOffset, (int64_t)elfSize, &g_plan) == 0) {
            g_has_plan = 1;
            if (cache_path) {
                save_plan_to_cache(cache_path, &g_plan);
            }
        }
    }

    try_apply_patch_locked();

    if (!g_patched && !g_watcher_started) {
        g_watcher_started = 1;
        pthread_t th;
        if (pthread_create(&th, NULL, watcher_thread, NULL) == 0) {
            pthread_detach(th);
        }
    }

    int ok = g_has_plan;
    pthread_mutex_unlock(&g_mutex);

    if (cache_path) (*env)->ReleaseStringUTFChars(env, jCachePath, cache_path);
    if (elf_path) (*env)->ReleaseStringUTFChars(env, jElfPath, elf_path);
    return ok ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_io_github_ikafly144_phoenix_xposed_tweaks_PhoenixNative_nativeOnLibraryLoaded(
    JNIEnv *env,
    jclass clazz
) {
    (void)env;
    (void)clazz;
    pthread_mutex_lock(&g_mutex);
    int applied = try_apply_patch_locked();
    pthread_mutex_unlock(&g_mutex);
    return applied ? JNI_TRUE : JNI_FALSE;
}
