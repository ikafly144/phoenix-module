#ifndef PHOENIX_ELF_H
#define PHOENIX_ELF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PHOENIX_PLAN_MAGIC    0x584E4850u /* "PHNX" */
#define PHOENIX_PLAN_VERSION  1u
#define PHOENIX_MAX_CODE_LEN  128u
#define PHOENIX_EXPECT_LEN    16u

#define PHOENIX_EM_X86_64     62u
#define PHOENIX_EM_AARCH64    183u

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t machine;
    uint32_t reserved;

    uint64_t access_va;
    uint32_t access_len;
    uint32_t access_exp_len;
    uint8_t  access_code[PHOENIX_MAX_CODE_LEN];
    uint8_t  access_expect[PHOENIX_EXPECT_LEN];

    uint64_t staff_va;
    uint64_t staff_size;
    uint64_t staff_key;
    uint64_t staff_read;
    uint64_t staff_drop;
    uint32_t staff_read_got;
    uint32_t staff_drop_got;
    uint32_t staff_tag_off;
    uint32_t staff_val_off;
    uint32_t staff_len;
    uint32_t staff_exp_len;
    uint8_t  staff_code[PHOENIX_MAX_CODE_LEN];
    uint8_t  staff_expect[PHOENIX_EXPECT_LEN];
} phoenix_patch_plan_t;

/**
 * Resolves the Phoenix access evaluator and is_staff hook from an ELF64 image
 * of liblibdiscord_wasm_host.so (supports arm64-v8a and x86_64).
 *
 * Returns 0 on success, non-zero on error (writing a message to err if non-NULL).
 */
int phoenix_resolve_elf(
    const uint8_t *data,
    size_t size,
    phoenix_patch_plan_t *out,
    char *err,
    size_t err_len
);

#ifdef __cplusplus
}
#endif

#endif /* PHOENIX_ELF_H */
