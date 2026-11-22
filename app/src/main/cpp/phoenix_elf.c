#include "phoenix_elf.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EXPERIMENT_STR   "2026-11-phoenix-app-access"
#define EXPERIMENT_LEN   26u
#define DEVTOOLS_ROW_STR "Show Dev Tools Widget"
#define DEVTOOLS_ROW_LEN 21u
#define DEV_ENV_STR      "LIBDISCORD_DEV_ANALYTICS"
#define DEV_ENV_LEN      24u

#define R_X86_64_RELATIVE  8u
#define R_AARCH64_RELATIVE 1027u

#define MAX_PT_LOADS 16
#define MAX_STR_HITS 32
#define MAX_XREFS    128
#define MAX_CALLS    256
#define MAX_INSNS    512

typedef struct {
    uint64_t vaddr;
    uint64_t offset;
    uint64_t filesz;
} pt_load_t;

typedef struct {
    uint64_t addr;
    uint64_t off;
    uint64_t size;
    int      found;
} elf_sec_t;

typedef struct {
    const uint8_t *d;
    size_t         size;
    uint16_t       machine;
    uint32_t       rtype;

    pt_load_t      loads[MAX_PT_LOADS];
    size_t         load_count;

    elf_sec_t      rodata;
    elf_sec_t      rela_dyn;
    elf_sec_t      eh_frame_hdr;
    elf_sec_t      text;

    uint64_t      *sorted_starts;
    size_t         starts_count;
    int            starts_inplace;
} elf_view_t;

static void set_err(char *err, size_t err_len, const char *fmt, ...) {
    if (!err || err_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, err_len, fmt, ap);
    va_end(ap);
}

static uint16_t read_u16(const uint8_t *p) {
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint32_t read_u32(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int32_t read_i32(const uint8_t *p) {
    int32_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t read_u64(const uint8_t *p) {
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int64_t read_i64(const uint8_t *p) {
    int64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static int va_to_off(const elf_view_t *e, uint64_t va, size_t len, size_t *out_off) {
    for (size_t i = 0; i < e->load_count; i++) {
        uint64_t v = e->loads[i].vaddr;
        uint64_t o = e->loads[i].offset;
        uint64_t sz = e->loads[i].filesz;
        if (va >= v && va < v + sz && (va - v) + len <= sz) {
            uint64_t foff = o + (va - v);
            if (foff + len <= e->size) {
                *out_off = (size_t)foff;
                return 0;
            }
        }
    }
    return -1;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

static size_t unique_u64(uint64_t *arr, size_t n) {
    if (n <= 1) return n;
    qsort(arr, n, sizeof(uint64_t), cmp_u64);
    size_t w = 1;
    for (size_t i = 1; i < n; i++) {
        if (arr[i] != arr[w - 1]) {
            arr[w++] = arr[i];
        }
    }
    return w;
}

static int init_starts(elf_view_t *e, char *err, size_t err_len) {
    if (e->eh_frame_hdr.off + 12 > e->size) {
        set_err(err, err_len, ".eh_frame_hdr header out of bounds");
        return -1;
    }
    uint32_t cnt = read_u32(e->d + e->eh_frame_hdr.off + 8);
    if (cnt == 0 || e->eh_frame_hdr.off + 12 + (uint64_t)cnt * 8 > e->size) {
        set_err(err, err_len, ".eh_frame_hdr table out of bounds (count=%u)", cnt);
        return -1;
    }
    e->starts_count = cnt;

    /* Check if the table is already sorted in-place (standard linker behavior). */
    const uint8_t *tbl = e->d + e->eh_frame_hdr.off + 12;
    uint64_t eh_addr = e->eh_frame_hdr.addr;
    int sorted = 1;
    uint64_t prev = (uint64_t)((int64_t)eh_addr + read_i32(tbl));
    for (uint32_t i = 1; i < cnt; i++) {
        uint64_t cur = (uint64_t)((int64_t)eh_addr + read_i32(tbl + (size_t)i * 8));
        if (cur < prev) {
            sorted = 0;
            break;
        }
        prev = cur;
    }

    if (sorted) {
        e->starts_inplace = 1;
        e->sorted_starts = NULL;
        return 0;
    }

    uint64_t *arr = (uint64_t *)malloc((size_t)cnt * sizeof(uint64_t));
    if (!arr) {
        set_err(err, err_len, "out of memory allocating .eh_frame_hdr starts");
        return -1;
    }
    for (uint32_t i = 0; i < cnt; i++) {
        arr[i] = (uint64_t)((int64_t)eh_addr + read_i32(tbl + (size_t)i * 8));
    }
    qsort(arr, cnt, sizeof(uint64_t), cmp_u64);
    e->sorted_starts = arr;
    e->starts_inplace = 0;
    return 0;
}

static uint64_t get_start_at(const elf_view_t *e, size_t idx) {
    if (!e->starts_inplace) {
        return e->sorted_starts[idx];
    }
    const uint8_t *tbl = e->d + e->eh_frame_hdr.off + 12;
    return (uint64_t)((int64_t)e->eh_frame_hdr.addr + read_i32(tbl + idx * 8));
}

static void func_bounds(const elf_view_t *e, uint64_t va, uint64_t *out_start, uint64_t *out_end) {
    size_t lo = 0;
    size_t hi = e->starts_count - 1;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo + 1) >> 1);
        if (get_start_at(e, mid) <= va) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    *out_start = get_start_at(e, lo);
    *out_end = (lo + 1 < e->starts_count) ? get_start_at(e, lo + 1) : (va + 0x1000u);
}

static size_t find_str_in_rodata(const elf_view_t *e, const char *needle, size_t needle_len, uint64_t *out, size_t max_out) {
    if (needle_len == 0 || e->rodata.size < needle_len) return 0;
    const uint8_t *hay = e->d + e->rodata.off;
    size_t limit = (size_t)(e->rodata.size - needle_len);
    size_t count = 0;
    uint8_t first = (uint8_t)needle[0];

    for (size_t i = 0; i <= limit; i++) {
        if (hay[i] == first && memcmp(hay + i, needle, needle_len) == 0) {
            if (count < max_out) {
                out[count++] = e->rodata.addr + i;
            }
        }
    }
    return count;
}

static int64_t read_sleb128(const uint8_t *d, size_t end, size_t *p) {
    uint64_t r = 0;
    unsigned s = 0;
    uint8_t b = 0;
    do {
        if (*p >= end) return 0;
        b = d[(*p)++];
        if (s < 64) {
            r |= (uint64_t)(b & 0x7fu) << s;
            s += 7;
        }
    } while (b & 0x80u);
    if ((b & 0x40u) && s < 64) {
        r |= (~0ULL) << s;
    }
    return (int64_t)r;
}

typedef void (*reloc_visitor_fn)(uint64_t slot, uint64_t target, void *ctx);

static void iterate_relocs(const elf_view_t *e, reloc_visitor_fn cb, void *ctx) {
    size_t off = (size_t)e->rela_dyn.off;
    size_t size = (size_t)e->rela_dyn.size;
    size_t end = off + size;
    const uint8_t *d = e->d;

    if (size >= 4 && d[off] == 'A' && d[off + 1] == 'P' && d[off + 2] == 'S' && d[off + 3] == '2') {
        size_t p = off + 4;
        int64_t n = read_sleb128(d, end, &p);
        int64_t roff = read_sleb128(d, end, &p);
        int64_t add = 0;
        int64_t cnt = 0;
        while (cnt < n && p < end) {
            int64_t gs = read_sleb128(d, end, &p);
            int64_t fl = read_sleb128(d, end, &p);
            int64_t god = (fl & 2) ? read_sleb128(d, end, &p) : 0;
            int64_t info = (fl & 1) ? read_sleb128(d, end, &p) : 0;
            if ((fl & 8) && (fl & 4)) {
                add += read_sleb128(d, end, &p);
            }
            for (int64_t k = 0; k < gs && cnt < n; k++, cnt++) {
                roff += (fl & 2) ? god : read_sleb128(d, end, &p);
                if (!(fl & 1)) {
                    info = read_sleb128(d, end, &p);
                }
                if ((fl & 8) && !(fl & 4)) {
                    add += read_sleb128(d, end, &p);
                }
                if ((uint32_t)(info & 0xffffffffLL) == e->rtype) {
                    cb((uint64_t)roff, (uint64_t)((fl & 8) ? add : 0), ctx);
                }
            }
        }
    } else {
        for (size_t i = off; i + 24 <= end; i += 24) {
            uint64_t r_offset = read_u64(d + i);
            uint64_t r_info = read_u64(d + i + 8);
            int64_t r_addend = read_i64(d + i + 16);
            if ((uint32_t)(r_info & 0xffffffffULL) == e->rtype) {
                cb(r_offset, (uint64_t)r_addend, ctx);
            }
        }
    }
}

typedef struct {
    const elf_view_t *e;
    const uint64_t   *exp_strs;
    size_t            exp_str_count;
    uint64_t          slots[MAX_STR_HITS];
    size_t            slot_count;
} exp_slot_ctx_t;

static void visit_exp_slots(uint64_t slot, uint64_t target, void *vctx) {
    exp_slot_ctx_t *ctx = (exp_slot_ctx_t *)vctx;
    for (size_t i = 0; i < ctx->exp_str_count; i++) {
        if (target == ctx->exp_strs[i]) {
            size_t len_off = 0;
            if (va_to_off(ctx->e, slot + 8, 8, &len_off) == 0) {
                if (read_u64(ctx->e->d + len_off) == EXPERIMENT_LEN) {
                    if (ctx->slot_count < MAX_STR_HITS) {
                        ctx->slots[ctx->slot_count++] = slot;
                    }
                }
            }
        }
    }
}

typedef struct {
    uint64_t *slots;
    uint64_t *targets;
    size_t    count;
} batch_reloc_ctx_t;

static void visit_batch_relocs(uint64_t slot, uint64_t target, void *vctx) {
    batch_reloc_ctx_t *ctx = (batch_reloc_ctx_t *)vctx;
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->slots[i] == slot) {
            ctx->targets[i] = target;
        }
    }
}

typedef struct {
    const uint64_t *exp_slots;
    size_t          exp_slot_count;
    uint64_t        exp_xrefs[MAX_XREFS];
    size_t          exp_xref_count;

    const uint64_t *row_strs;
    size_t          row_str_count;
    uint64_t        row_xrefs[MAX_XREFS];
    size_t          row_xref_count;

    const uint64_t *env_strs;
    size_t          env_str_count;
    uint64_t        env_xrefs[MAX_XREFS];
    size_t          env_xref_count;
} xref_collector_t;

static void check_and_record_xref(xref_collector_t *c, uint64_t pc, uint64_t tgt) {
    for (size_t i = 0; i < c->exp_slot_count; i++) {
        if (tgt == c->exp_slots[i] && c->exp_xref_count < MAX_XREFS) {
            c->exp_xrefs[c->exp_xref_count++] = pc;
        }
    }
    for (size_t i = 0; i < c->row_str_count; i++) {
        if (tgt == c->row_strs[i] && c->row_xref_count < MAX_XREFS) {
            c->row_xrefs[c->row_xref_count++] = pc;
        }
    }
    for (size_t i = 0; i < c->env_str_count; i++) {
        if (tgt == c->env_strs[i] && c->env_xref_count < MAX_XREFS) {
            c->env_xrefs[c->env_xref_count++] = pc;
        }
    }
}

static int page_near_any_target(const xref_collector_t *c, uint64_t page) {
    /* On arm64, add imm12 reaches [page, page+0xfff] and ldr 64-bit imm12*8 reaches [page, page+0x7ff8]. */
    for (size_t i = 0; i < c->exp_slot_count; i++) {
        uint64_t t = c->exp_slots[i];
        if (t >= page && t - page < 0x8000u) return 1;
    }
    for (size_t i = 0; i < c->row_str_count; i++) {
        uint64_t t = c->row_strs[i];
        if (t >= page && t - page < 0x8000u) return 1;
    }
    for (size_t i = 0; i < c->env_str_count; i++) {
        uint64_t t = c->env_strs[i];
        if (t >= page && t - page < 0x8000u) return 1;
    }
    return 0;
}

static void scan_xrefs_arm64(const elf_view_t *e, xref_collector_t *c) {
    const uint8_t *text = e->d + e->text.off;
    size_t words = (size_t)(e->text.size / 4);
    uint64_t base_addr = e->text.addr;

    for (size_t i = 0; i < words; i++) {
        uint32_t a = read_u32(text + i * 4);
        if ((a & 0x9f000000u) != 0x90000000u) continue;
        uint32_t rd = a & 31u;
        uint64_t pc = base_addr + (uint64_t)i * 4;
        int64_t imm = (int64_t)(((a >> 29) & 3u) | (((a >> 5) & 0x7ffffu) << 2));
        if (imm & (1LL << 20)) imm -= (1LL << 21);
        uint64_t page = (pc & ~0xfffULL) + (uint64_t)(imm * 4096);

        if (!page_near_any_target(c, page)) continue;

        for (size_t k = 1; k <= 4 && i + k < words; k++) {
            uint32_t n = read_u32(text + (i + k) * 4);
            if (((n >> 5) & 31u) != rd) continue;
            if ((n & 0xffc00000u) == 0x91000000u) {
                uint64_t t = page + ((n >> 10) & 0xfffu);
                check_and_record_xref(c, pc, t);
            } else if ((n & 0xffc00000u) == 0xf9400000u) {
                uint64_t t = page + ((n >> 10) & 0xfffu) * 8u;
                check_and_record_xref(c, pc, t);
            }
        }
    }
}

static void scan_xrefs_x86(const elf_view_t *e, xref_collector_t *c) {
    const uint8_t *t = e->d + e->text.off;
    size_t size = (size_t)e->text.size;
    uint64_t addr = e->text.addr;
    if (size < 7) return;

    for (size_t i = 0; i < size - 6; ) {
        uint8_t b = t[i];
        size_t n = 0;
        if ((b == 0x48 || b == 0x4c) && (t[i + 1] == 0x8d || t[i + 1] == 0x8b) && (t[i + 2] & 0xc7) == 0x05) {
            n = 3;
        } else if (b == 0xff && (t[i + 1] == 0x15 || t[i + 1] == 0x25)) {
            n = 2;
        }
        if (!n) {
            i++;
            continue;
        }
        uint64_t pc = addr + i;
        int32_t disp = read_i32(t + i + n);
        uint64_t tgt = (uint64_t)((int64_t)(pc + n + 4) + disp);
        check_and_record_xref(c, pc, tgt);
        i += n;
    }
}

static int refs_in_func(const elf_view_t *e, uint64_t faddr, const uint64_t *env_xrefs, size_t env_xref_count) {
    uint64_t a = 0, b = 0;
    func_bounds(e, faddr, &a, &b);
    for (size_t i = 0; i < env_xref_count; i++) {
        if (env_xrefs[i] >= a && env_xrefs[i] < b) {
            return 1;
        }
    }
    return 0;
}

/* --- ARM64 Helpers ------------------------------------------------------------------------ */

static int arm64_bl_target(uint32_t w, uint64_t pc, uint64_t *out_target) {
    if ((w & 0xfc000000u) == 0x94000000u) {
        int32_t imm26 = ((int32_t)(w << 6)) >> 6;
        *out_target = (uint64_t)((int64_t)pc + (int64_t)imm26 * 4);
        return 1;
    }
    return 0;
}

static uint32_t enc_arm64_bl(uint64_t pc, uint64_t target) {
    int64_t diff = ((int64_t)target - (int64_t)pc) >> 2;
    return 0x94000000u | ((uint32_t)diff & 0x03ffffffu);
}

static uint32_t enc_arm64_adrp(uint64_t pc, uint64_t target, uint32_t rd) {
    int64_t page_diff = ((int64_t)(target >> 12) - (int64_t)(pc >> 12)) & 0x1fffffLL;
    uint32_t immlo = (uint32_t)(page_diff & 3);
    uint32_t immhi = (uint32_t)((page_diff >> 2) & 0x7ffff);
    return 0x90000000u | (immlo << 29) | (immhi << 5) | (rd & 31u);
}

static int enc_arm64_movz(uint32_t rd, uint32_t imm, uint32_t *out_word) {
    if (imm > 0xffffu) return -1;
    *out_word = 0xd2800000u | (imm << 5) | (rd & 31u);
    return 0;
}

static int resolve_arm64_is_staff(
    const elf_view_t *e,
    const xref_collector_t *xc,
    phoenix_patch_plan_t *out,
    char *err,
    size_t err_len
) {
    uint64_t found[MAX_STR_HITS];
    size_t found_count = 0;

    uint64_t row_refs[MAX_XREFS];
    memcpy(row_refs, xc->row_xrefs, xc->row_xref_count * sizeof(uint64_t));
    size_t row_ref_count = unique_u64(row_refs, xc->row_xref_count);

    for (size_t r_idx = 0; r_idx < row_ref_count; r_idx++) {
        uint64_t r = row_refs[r_idx];
        uint64_t f = 0, f_end = 0;
        func_bounds(e, r, &f, &f_end);
        if (r <= f || r - f > 0x20000u) continue;

        uint64_t calls[MAX_CALLS];
        size_t call_count = 0;
        for (uint64_t pc = f; pc < r; pc += 4) {
            size_t off = 0;
            if (va_to_off(e, pc, 4, &off) != 0) break;
            uint32_t w = read_u32(e->d + off);
            uint64_t tgt = 0;
            if (arm64_bl_target(w, pc, &tgt) && call_count < MAX_CALLS) {
                calls[call_count++] = tgt;
            }
        }
        for (size_t i = 0; i + 1 < call_count; i++) {
            if (refs_in_func(e, calls[i], xc->env_xrefs, xc->env_xref_count)) {
                if (found_count < MAX_STR_HITS) {
                    found[found_count++] = calls[i + 1];
                }
            }
        }
    }

    found_count = unique_u64(found, found_count);
    if (found_count != 1) {
        set_err(err, err_len, "is_staff (arm64): expected 1 match, got %zu", found_count);
        return -1;
    }

    uint64_t f = found[0];
    uint64_t f_start = 0, f_end = 0;
    func_bounds(e, f, &f_start, &f_end);
    if (f_end <= f || (f_end - f) / 4 > MAX_INSNS) {
        set_err(err, err_len, "is_staff (arm64): invalid function bounds [0x%llx, 0x%llx)",
                (unsigned long long)f, (unsigned long long)f_end);
        return -1;
    }

    size_t ins_count = (size_t)((f_end - f) / 4);
    uint64_t pcs[MAX_INSNS];
    uint32_t words[MAX_INSNS];
    uint64_t calls[MAX_CALLS];
    size_t call_count = 0;

    for (size_t i = 0; i < ins_count; i++) {
        pcs[i] = f + (uint64_t)i * 4;
        size_t off = 0;
        if (va_to_off(e, pcs[i], 4, &off) != 0) {
            set_err(err, err_len, "is_staff (arm64): unmapped instruction at 0x%llx", (unsigned long long)pcs[i]);
            return -1;
        }
        words[i] = read_u32(e->d + off);
        uint64_t tgt = 0;
        if (arm64_bl_target(words[i], pcs[i], &tgt) && call_count < MAX_CALLS) {
            calls[call_count++] = tgt;
        }
    }

    if (call_count != 2) {
        set_err(err, err_len, "is_staff (arm64): expected 2 bl calls, got %zu", call_count);
        return -1;
    }

    int has_key = 0, has_base = 0, has_tags = 0;
    uint64_t key = 0;
    uint32_t base = 0;
    uint32_t tag_reg = 0, val_reg = 0;
    uint32_t loads[32] = {0};
    uint8_t has_load[32] = {0};

    for (size_t i = 0; i < ins_count; i++) {
        uint64_t pc = pcs[i];
        uint32_t w = words[i];
        if ((w & 0x9f00001fu) == 0x90000001u && i + 1 < ins_count) {
            uint32_t n = words[i + 1];
            if ((n & 0xffc003ffu) == 0x91000021u) {
                int64_t imm = (int64_t)(((w >> 29) & 3u) | (((w >> 5) & 0x7ffffu) << 2));
                if (imm & (1LL << 20)) imm -= (1LL << 21);
                key = (pc & ~0xfffULL) + (uint64_t)(imm * 4096) + ((n >> 10) & 0xfffu);
                has_key = 1;
            }
        }
        if ((w & 0xffc00000u) == 0x91400000u && (w & 31u) == ((w >> 5) & 31u)) {
            base = ((w >> 10) & 0xfffu) * 4096u;
            has_base = 1;
        }
        if ((w & 0xffc00000u) == 0xb9400000u) {
            uint32_t reg = w & 31u;
            loads[reg] = ((w >> 10) & 0xfffu) * 4u;
            has_load[reg] = 1;
        }
        if ((w & 0xfffffc1fu) == 0x7100001fu && has_load[(w >> 5) & 31u] && i + 1 < ins_count) {
            uint32_t n = words[i + 1];
            if ((n & 0xfffffc00u) == 0x1a9f1000u && has_load[(n >> 5) & 31u]) {
                tag_reg = (w >> 5) & 31u;
                val_reg = (n >> 5) & 31u;
                has_tags = 1;
            }
        }
    }

    if (!has_key || !has_base || !has_tags) {
        set_err(err, err_len, "is_staff (arm64): shape not recognised (key=%d base=%d tags=%d)",
                has_key, has_base, has_tags);
        return -1;
    }

    uint32_t tag_off = base + loads[tag_reg];
    uint32_t val_off = base + loads[val_reg];
    uint32_t movz_tag = 0, movz_val = 0;
    if (enc_arm64_movz(10, tag_off, &movz_tag) != 0 || enc_arm64_movz(10, val_off, &movz_val) != 0) {
        set_err(err, err_len, "is_staff (arm64): flag_override offset too large (tag=0x%x val=0x%x)", tag_off, val_off);
        return -1;
    }

    uint32_t hook_words[22] = {
        0xd10103ffu,                                      /* sub sp, sp, #0x40 */
        0xa9027bfdu,                                      /* stp x29, x30, [sp, #0x20] */
        0x910083fdu,                                      /* add x29, sp, #0x20 */
        enc_arm64_adrp(f + 12, key, 1),                   /* adrp x1, KEY */
        0x91000021u | ((uint32_t)(key & 0xfffu) << 10),   /* add x1, x1, :lo12:KEY */
        0x910003e8u,                                      /* mov x8, sp */
        enc_arm64_bl(f + 24, calls[0]),                   /* bl read_state */
        0xf94003e9u,                                      /* ldr x9, [sp] */
        0xb4000000u | (8u << 5) | 9u,                     /* cbz x9, +32 (-> mov x0, sp) */
        movz_tag,                                         /* mov x10, #TAG */
        0x5280002bu,                                      /* mov w11, #1 */
        0x382a692bu,                                      /* strb w11, [x9, x10] */
        movz_val,                                         /* mov x10, #VAL */
        0xb86a692bu,                                      /* ldr w11, [x9, x10] */
        0x3200016bu,                                      /* orr w11, w11, #1 */
        0xb82a692bu,                                      /* str w11, [x9, x10] */
        0x910003e0u,                                      /* mov x0, sp */
        enc_arm64_bl(f + 68, calls[1]),                   /* bl drop */
        0x52800020u,                                      /* mov w0, #1 */
        0xa9427bfdu,                                      /* ldp x29, x30, [sp, #0x20] */
        0x910103ffu,                                      /* add sp, sp, #0x40 */
        0xd65f03c0u                                       /* ret */
    };

    if (sizeof(hook_words) > f_end - f) {
        set_err(err, err_len, "is_staff (arm64): hook (%zu bytes) does not fit in function (%llu bytes)",
                sizeof(hook_words), (unsigned long long)(f_end - f));
        return -1;
    }

    out->staff_va = f;
    out->staff_size = f_end - f;
    out->staff_key = key;
    out->staff_read = calls[0];
    out->staff_drop = calls[1];
    out->staff_read_got = 0;
    out->staff_drop_got = 0;
    out->staff_tag_off = tag_off;
    out->staff_val_off = val_off;
    out->staff_len = (uint32_t)sizeof(hook_words);
    memcpy(out->staff_code, hook_words, sizeof(hook_words));

    size_t f_off = 0;
    va_to_off(e, f, PHOENIX_EXPECT_LEN, &f_off);
    out->staff_exp_len = PHOENIX_EXPECT_LEN;
    memcpy(out->staff_expect, e->d + f_off, PHOENIX_EXPECT_LEN);
    return 0;
}

/* --- X86_64 Instruction Decoder & Helpers ------------------------------------------------- */

typedef struct {
    uint64_t pc;
    uint32_t len;
    uint16_t op;
    uint8_t  rex;
    int      has_modrm;
    uint8_t  modrm;
    int      has_disp;
    int32_t  disp;
    int      rip;
    int      has_imm;
    uint8_t  imm8;
    int      call_kind; /* 0 = none, 1 = direct, 2 = got */
    uint64_t call_target;
} x86_insn_t;

static int is_modrm1(uint8_t op) {
    if (op < 0x40 && (op & 7) < 4) return 1;
    if (op >= 0x80 && op < 0x90) return 1;
    switch (op) {
        case 0x63: case 0x69: case 0x6b:
        case 0xc0: case 0xc1: case 0xc6: case 0xc7:
        case 0xd0: case 0xd1: case 0xd2: case 0xd3:
        case 0xf6: case 0xf7: case 0xfe: case 0xff:
            return 1;
        default:
            return 0;
    }
}

static int decode_x86(const uint8_t *u8, size_t max_len, uint64_t pc, x86_insn_t *out) {
    memset(out, 0, sizeof(*out));
    size_t o = 0;
    uint8_t rex = 0;
    int opsz = 0;

    while (o < max_len) {
        uint8_t b = u8[o];
        if (b == 0x66) {
            opsz = 1;
            o++;
        } else if (b == 0x67 || b == 0xf2 || b == 0xf3 || b == 0xf0 ||
                   b == 0x2e || b == 0x3e || b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65) {
            o++;
        } else {
            break;
        }
    }
    if (o < max_len && (u8[o] & 0xf0u) == 0x40u) {
        rex = u8[o++];
    }
    if (o >= max_len) return -1;

    uint8_t op1 = u8[o++];
    uint16_t op = op1;
    size_t z = opsz ? 2 : 4;
    int modrm = 0;
    size_t imm = 0;
    size_t rel = 0;

    if (op1 == 0x0f) {
        if (o >= max_len) return -1;
        uint8_t op2 = u8[o++];
        op = (uint16_t)(0x0f00u | op2);
        if (op2 == 0x38) {
            o++;
            modrm = 1;
        } else if (op2 == 0x3a) {
            o++;
            modrm = 1;
            imm = 1;
        } else if (op2 >= 0x80 && op2 <= 0x8f) {
            rel = 4;
        } else if (op2 == 0x05 || op2 == 0x0b || op2 == 0xa2 || op2 == 0x31 || (op2 >= 0xc8 && op2 <= 0xcf)) {
            /* no operands */
        } else {
            modrm = 1;
            if (op2 == 0x70 || op2 == 0x71 || op2 == 0x72 || op2 == 0x73 ||
                op2 == 0xa4 || op2 == 0xac || op2 == 0xba || op2 == 0xc2 ||
                op2 == 0xc4 || op2 == 0xc5 || op2 == 0xc6) {
                imm = 1;
            }
        }
    } else if (is_modrm1(op1)) {
        modrm = 1;
        if (op1 == 0x80 || op1 == 0x83 || op1 == 0x6b || op1 == 0xc0 || op1 == 0xc1 || op1 == 0xc6) {
            imm = 1;
        } else if (op1 == 0x81 || op1 == 0x69 || op1 == 0xc7) {
            imm = z;
        } else if (op1 == 0xf6 || op1 == 0xf7) {
            if (o >= max_len) return -1;
            if (((u8[o] >> 3) & 7u) < 2u) {
                imm = (op1 == 0xf6) ? 1 : z;
            }
        }
    } else if (op1 < 0x40 && (op1 & 7u) == 4u) {
        imm = 1;
    } else if (op1 < 0x40 && (op1 & 7u) == 5u) {
        imm = z;
    } else if ((op1 >= 0x50 && op1 <= 0x5f) || (op1 >= 0x90 && op1 <= 0x9f && op1 != 0x9a) ||
               op1 == 0xc3 || op1 == 0xc9 || op1 == 0xcc || op1 == 0xf4) {
        /* no operands */
    } else if (op1 == 0x68) {
        imm = z;
    } else if (op1 == 0x6a || op1 == 0xa8 || (op1 >= 0xb0 && op1 <= 0xb7)) {
        imm = 1;
    } else if (op1 == 0xa9) {
        imm = z;
    } else if (op1 >= 0xb8 && op1 <= 0xbf) {
        imm = (rex & 8u) ? 8 : z;
    } else if (op1 == 0xc2) {
        imm = 2;
    } else if ((op1 >= 0x70 && op1 <= 0x7f) || op1 == 0xeb) {
        rel = 1;
    } else if (op1 == 0xe8 || op1 == 0xe9) {
        rel = 4;
    } else {
        return -1;
    }

    int has_disp = 0;
    int32_t disp = 0;
    int rip = 0;
    uint8_t m = 0;
    if (modrm) {
        if (o >= max_len) return -1;
        m = u8[o++];
        uint8_t mod = m >> 6;
        uint8_t rm = m & 7u;
        uint8_t base = rm;
        if (mod != 3 && rm == 4) {
            if (o >= max_len) return -1;
            base = u8[o++] & 7u;
        }
        if (mod == 1) {
            if (o + 1 > max_len) return -1;
            disp = (int8_t)u8[o];
            o += 1;
            has_disp = 1;
        } else if (mod == 2 || (mod == 0 && base == 5)) {
            if (o + 4 > max_len) return -1;
            disp = read_i32(u8 + o);
            o += 4;
            has_disp = 1;
            rip = (mod == 0 && rm == 5);
        }
    }

    size_t imm_at = o;
    o += imm;
    size_t total_len = o + rel;
    if (total_len > max_len) return -1;

    out->pc = pc;
    out->len = (uint32_t)total_len;
    out->op = op;
    out->rex = rex;
    out->has_modrm = modrm;
    out->modrm = m;
    out->has_disp = has_disp;
    out->disp = disp;
    out->rip = rip;
    out->has_imm = (imm > 0);
    out->imm8 = (imm > 0) ? u8[imm_at] : 0;

    if (op == 0xe8) {
        int32_t rel32 = read_i32(u8 + o);
        out->call_kind = 1;
        out->call_target = (uint64_t)((int64_t)(pc + total_len) + rel32);
    } else if (op == 0xff && modrm && m == 0x15) {
        out->call_kind = 2;
        out->call_target = (uint64_t)((int64_t)(pc + total_len) + disp);
    }
    return 0;
}

static int is_x86_tag_cmp(const x86_insn_t *i) {
    return i->op == 0x80 && i->has_modrm &&
           (i->modrm & 0xc7u) != 0xc0u &&
           ((i->modrm >> 3) & 7u) == 7u &&
           (i->modrm & 7u) == 0u &&
           (i->modrm >> 6) != 0u &&
           i->has_disp && i->disp > 0 &&
           i->has_imm && i->imm8 == 0;
}

static size_t append_rax_disp(uint8_t *dst, uint8_t r, int32_t d) {
    if (d == 0) {
        dst[0] = (uint8_t)(r << 3);
        return 1;
    } else if (d >= -128 && d < 128) {
        dst[0] = (uint8_t)(0x40u | (r << 3));
        dst[1] = (uint8_t)(d & 0xff);
        return 2;
    } else {
        dst[0] = (uint8_t)(0x80u | (r << 3));
        uint32_t u = (uint32_t)d;
        memcpy(dst + 1, &u, 4);
        return 5;
    }
}

static size_t append_rip_rel(uint8_t *buf, size_t cur_len, uint64_t func_va, const uint8_t *pre, size_t pre_len, uint64_t target) {
    memcpy(buf + cur_len, pre, pre_len);
    cur_len += pre_len;
    int32_t rel = (int32_t)((int64_t)target - (int64_t)(func_va + cur_len + 4));
    memcpy(buf + cur_len, &rel, 4);
    return cur_len + 4;
}

static int resolve_x86_is_staff(
    const elf_view_t *e,
    const xref_collector_t *xc,
    phoenix_patch_plan_t *out,
    char *err,
    size_t err_len
) {
    /* builders: map func_start -> last row xref in that func (same as x86.js builders Map) */
    uint64_t row_refs[MAX_XREFS];
    memcpy(row_refs, xc->row_xrefs, xc->row_xref_count * sizeof(uint64_t));
    size_t row_ref_count = unique_u64(row_refs, xc->row_xref_count);

    uint64_t builder_f[MAX_STR_HITS];
    uint64_t builder_r[MAX_STR_HITS];
    size_t builder_count = 0;

    for (size_t i = 0; i < row_ref_count; i++) {
        uint64_t r = row_refs[i];
        uint64_t f = 0, f_end = 0;
        func_bounds(e, r, &f, &f_end);
        size_t idx = builder_count;
        for (size_t j = 0; j < builder_count; j++) {
            if (builder_f[j] == f) {
                idx = j;
                break;
            }
        }
        if (idx == builder_count && builder_count < MAX_STR_HITS) {
            builder_count++;
        }
        if (idx < MAX_STR_HITS) {
            builder_f[idx] = f;
            builder_r[idx] = r;
        }
    }

    uint64_t found[MAX_STR_HITS];
    size_t found_count = 0;

    for (size_t b_idx = 0; b_idx < builder_count; b_idx++) {
        uint64_t f = builder_f[b_idx];
        uint64_t ref = builder_r[b_idx];
        if (ref <= f || ref - f > 0x20000u) continue;

        size_t f_off = 0;
        size_t span = (size_t)(ref - f);
        if (va_to_off(e, f, span, &f_off) != 0) continue;

        int call_kinds[MAX_CALLS];
        uint64_t call_addrs[MAX_CALLS];
        uint64_t resolved[MAX_CALLS];
        size_t call_count = 0;

        for (uint64_t pc = f; pc < ref; ) {
            x86_insn_t ins;
            size_t rem = (size_t)(ref - pc);
            if (decode_x86(e->d + f_off + (pc - f), rem, pc, &ins) != 0 || ins.len == 0) {
                break;
            }
            if (ins.call_kind != 0 && call_count < MAX_CALLS) {
                call_kinds[call_count] = ins.call_kind;
                call_addrs[call_count] = ins.call_target;
                resolved[call_count] = (ins.call_kind == 1) ? ins.call_target : 0;
                call_count++;
            }
            pc += ins.len;
        }

        /* Resolve any GOT call slots in a single pass */
        uint64_t got_slots[MAX_CALLS];
        uint64_t got_targets[MAX_CALLS];
        size_t got_count = 0;
        for (size_t i = 0; i < call_count; i++) {
            if (call_kinds[i] == 2) {
                got_slots[got_count] = call_addrs[i];
                got_targets[got_count] = 0;
                got_count++;
            }
        }
        if (got_count > 0) {
            batch_reloc_ctx_t bctx = { got_slots, got_targets, got_count };
            iterate_relocs(e, visit_batch_relocs, &bctx);
            size_t g = 0;
            for (size_t i = 0; i < call_count; i++) {
                if (call_kinds[i] == 2) {
                    resolved[i] = got_targets[g++];
                }
            }
        }

        for (size_t i = 0; i + 1 < call_count; i++) {
            if (resolved[i] != 0 && refs_in_func(e, resolved[i], xc->env_xrefs, xc->env_xref_count)) {
                if (found_count < MAX_STR_HITS) {
                    found[found_count++] = resolved[i + 1];
                }
            }
        }
    }

    found_count = unique_u64(found, found_count);
    if (found_count != 1) {
        set_err(err, err_len, "is_staff (x86_64): expected 1 match, got %zu", found_count);
        return -1;
    }

    uint64_t f = found[0];
    uint64_t f_start = 0, f_end = 0;
    func_bounds(e, f, &f_start, &f_end);
    if (f_end <= f || f_end - f > 0x4000u) {
        set_err(err, err_len, "is_staff (x86_64): invalid function bounds [0x%llx, 0x%llx)",
                (unsigned long long)f, (unsigned long long)f_end);
        return -1;
    }

    size_t f_off = 0;
    size_t f_size = (size_t)(f_end - f);
    if (va_to_off(e, f, f_size, &f_off) != 0) {
        set_err(err, err_len, "is_staff (x86_64): unmapped function at 0x%llx", (unsigned long long)f);
        return -1;
    }

    x86_insn_t insns[MAX_INSNS];
    size_t insn_count = 0;
    int cs_kind[MAX_CALLS];
    uint64_t cs_target[MAX_CALLS];
    size_t cs_count = 0;

    for (uint64_t pc = f; pc < f_end && insn_count < MAX_INSNS; ) {
        x86_insn_t *ins = &insns[insn_count];
        if (decode_x86(e->d + f_off + (pc - f), (size_t)(f_end - pc), pc, ins) != 0 || ins->len == 0) {
            set_err(err, err_len, "is_staff (x86_64): failed decoding instruction at 0x%llx", (unsigned long long)pc);
            return -1;
        }
        if (ins->call_kind != 0 && cs_count < MAX_CALLS) {
            cs_kind[cs_count] = ins->call_kind;
            cs_target[cs_count] = ins->call_target;
            cs_count++;
        }
        pc += ins->len;
        insn_count++;
    }

    if (cs_count != 2) {
        set_err(err, err_len, "is_staff (x86_64): expected 2 calls, got %zu", cs_count);
        return -1;
    }

    /* lea rdx, [rip+KEY] */
    uint64_t keys[16];
    size_t key_count = 0;
    for (size_t i = 0; i < insn_count; i++) {
        const x86_insn_t *ins = &insns[i];
        if (ins->op == 0x8d && ins->rip && (ins->rex & 0xcu) == 8u && ((ins->modrm >> 3) & 7u) == 2u) {
            if (key_count < 16) {
                keys[key_count++] = (uint64_t)((int64_t)(ins->pc + ins->len) + ins->disp);
            }
        }
    }
    key_count = unique_u64(keys, key_count);
    if (key_count != 1) {
        set_err(err, err_len, "is_staff key (x86_64): expected 1 match, got %zu", key_count);
        return -1;
    }
    uint64_t key = keys[0];

    /* cmp byte ptr [rax+TAG], 0 */
    uint64_t tags[16];
    size_t tag_count = 0;
    for (size_t i = 0; i < insn_count; i++) {
        if (is_x86_tag_cmp(&insns[i]) && tag_count < 16) {
            tags[tag_count++] = (uint64_t)(uint32_t)insns[i].disp;
        }
    }
    tag_count = unique_u64(tags, tag_count);
    if (tag_count != 1) {
        set_err(err, err_len, "flag_override tag (x86_64): expected 1 match, got %zu", tag_count);
        return -1;
    }
    int32_t tag = (int32_t)tags[0];

    size_t k = 0;
    for (; k < insn_count; k++) {
        if (is_x86_tag_cmp(&insns[k]) && insns[k].disp == tag) break;
    }

    uint64_t vals[16];
    size_t val_count = 0;
    for (size_t i = k; i < k + 4 && i < insn_count; i++) {
        const x86_insn_t *ins = &insns[i];
        if (ins->op == 0x8b && !(ins->rex & 0xcu) && ins->has_modrm &&
            (ins->modrm & 7u) == 0u && (ins->modrm >> 6) != 0u && (ins->modrm >> 6) != 3u &&
            ins->has_disp && ins->disp > 0) {
            if (val_count < 16) {
                vals[val_count++] = (uint64_t)(uint32_t)ins->disp;
            }
        }
    }
    val_count = unique_u64(vals, val_count);
    if (val_count != 1) {
        set_err(err, err_len, "flag_override value (x86_64): expected 1 match, got %zu", val_count);
        return -1;
    }
    int32_t val = (int32_t)vals[0];

    /* Assemble x86_64 hook (byte-identical to web/lib/x86.js hook(s)) */
    uint8_t b[PHOENIX_MAX_CODE_LEN];
    size_t blen = 0;

    static const uint8_t prolog[] = {
        0x53, 0x48, 0x83, 0xec, 0x40, 0x48, 0x89, 0xfe, 0x48, 0x89, 0xe7
    };
    memcpy(b + blen, prolog, sizeof(prolog));
    blen += sizeof(prolog);

    static const uint8_t lea_rdx[] = { 0x48, 0x8d, 0x15 };
    blen = append_rip_rel(b, blen, f, lea_rdx, sizeof(lea_rdx), key);

    static const uint8_t call_got[] = { 0xff, 0x15 };
    static const uint8_t call_dir[] = { 0xe8 };
    if (cs_kind[0] == 2) {
        blen = append_rip_rel(b, blen, f, call_got, sizeof(call_got), cs_target[0]);
    } else {
        blen = append_rip_rel(b, blen, f, call_dir, sizeof(call_dir), cs_target[0]);
    }

    static const uint8_t load_guard[] = { 0x48, 0x8b, 0x04, 0x24, 0x48, 0x85, 0xc0 };
    memcpy(b + blen, load_guard, sizeof(load_guard));
    blen += sizeof(load_guard);

    uint8_t set_buf[32];
    size_t set_len = 0;
    set_buf[set_len++] = 0xc6;
    set_len += append_rax_disp(set_buf + set_len, 0, tag);
    set_buf[set_len++] = 1;
    set_buf[set_len++] = 0x83;
    set_len += append_rax_disp(set_buf + set_len, 1, val);
    set_buf[set_len++] = 1;

    b[blen++] = 0x74;
    b[blen++] = (uint8_t)set_len;
    memcpy(b + blen, set_buf, set_len);
    blen += set_len;

    static const uint8_t mov_rdi_rsp[] = { 0x48, 0x89, 0xe7 };
    memcpy(b + blen, mov_rdi_rsp, sizeof(mov_rdi_rsp));
    blen += sizeof(mov_rdi_rsp);

    if (cs_kind[1] == 2) {
        blen = append_rip_rel(b, blen, f, call_got, sizeof(call_got), cs_target[1]);
    } else {
        blen = append_rip_rel(b, blen, f, call_dir, sizeof(call_dir), cs_target[1]);
    }

    static const uint8_t epilog[] = { 0xb0, 0x01, 0x48, 0x83, 0xc4, 0x40, 0x5b, 0xc3 };
    memcpy(b + blen, epilog, sizeof(epilog));
    blen += sizeof(epilog);

    if (blen > f_size) {
        set_err(err, err_len, "is_staff (x86_64): hook (%zu bytes) does not fit in function (%zu bytes)",
                blen, f_size);
        return -1;
    }

    out->staff_va = f;
    out->staff_size = f_size;
    out->staff_key = key;
    out->staff_read = cs_target[0];
    out->staff_drop = cs_target[1];
    out->staff_read_got = (cs_kind[0] == 2) ? 1u : 0u;
    out->staff_drop_got = (cs_kind[1] == 2) ? 1u : 0u;
    out->staff_tag_off = (uint32_t)tag;
    out->staff_val_off = (uint32_t)val;
    out->staff_len = (uint32_t)blen;
    memcpy(out->staff_code, b, blen);

    out->staff_exp_len = PHOENIX_EXPECT_LEN;
    memcpy(out->staff_expect, e->d + f_off, PHOENIX_EXPECT_LEN);
    return 0;
}

/* --- Main Entry Point --------------------------------------------------------------------- */

int phoenix_resolve_elf(
    const uint8_t *data,
    size_t size,
    phoenix_patch_plan_t *out,
    char *err,
    size_t err_len
) {
    if (!data || !out || size < 64) {
        set_err(err, err_len, "invalid ELF buffer");
        return -1;
    }
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F' || data[4] != 2) {
        set_err(err, err_len, "not an ELF64 file");
        return -1;
    }

    memset(out, 0, sizeof(*out));
    elf_view_t e;
    memset(&e, 0, sizeof(e));
    e.d = data;
    e.size = size;
    e.machine = read_u16(data + 18);

    if (e.machine == PHOENIX_EM_AARCH64) {
        e.rtype = R_AARCH64_RELATIVE;
    } else if (e.machine == PHOENIX_EM_X86_64) {
        e.rtype = R_X86_64_RELATIVE;
    } else {
        set_err(err, err_len, "unsupported ELF machine: %u", (unsigned)e.machine);
        return -1;
    }

    uint64_t phoff = read_u64(data + 32);
    uint64_t shoff = read_u64(data + 40);
    uint16_t phentsize = read_u16(data + 54);
    uint16_t phnum = read_u16(data + 56);
    uint16_t shentsize = read_u16(data + 58);
    uint16_t shnum = read_u16(data + 60);
    uint16_t shstrndx = read_u16(data + 62);

    if (phentsize < 56 || phoff + (uint64_t)phnum * phentsize > size) {
        set_err(err, err_len, "program headers out of bounds");
        return -1;
    }
    if (shentsize < 64 || shnum == 0 || shoff + (uint64_t)shnum * shentsize > size || shstrndx >= shnum) {
        set_err(err, err_len, "section headers out of bounds");
        return -1;
    }

    for (uint16_t i = 0; i < phnum; i++) {
        const uint8_t *ph = data + phoff + (size_t)i * phentsize;
        if (read_u32(ph) == 1u) { /* PT_LOAD */
            if (e.load_count < MAX_PT_LOADS) {
                e.loads[e.load_count].offset = read_u64(ph + 8);
                e.loads[e.load_count].vaddr = read_u64(ph + 16);
                e.loads[e.load_count].filesz = read_u64(ph + 32);
                e.load_count++;
            }
        }
    }

    const uint8_t *shstr_sec = data + shoff + (size_t)shstrndx * shentsize;
    uint64_t shstr_off = read_u64(shstr_sec + 24);
    uint64_t shstr_size = read_u64(shstr_sec + 32);
    if (shstr_off + shstr_size > size) {
        set_err(err, err_len, ".shstrtab out of bounds");
        return -1;
    }

    for (uint16_t i = 0; i < shnum; i++) {
        const uint8_t *sh = data + shoff + (size_t)i * shentsize;
        uint32_t name_idx = read_u32(sh);
        uint64_t s_addr = read_u64(sh + 16);
        uint64_t s_off = read_u64(sh + 24);
        uint64_t s_size = read_u64(sh + 32);
        if (name_idx >= shstr_size || s_off + s_size > size) continue;

        const char *sname = (const char *)(data + shstr_off + name_idx);
        size_t max_nlen = (size_t)(shstr_size - name_idx);
        if (memchr(sname, '\0', max_nlen) == NULL) continue;

        if (strcmp(sname, ".rodata") == 0) {
            e.rodata = (elf_sec_t){ s_addr, s_off, s_size, 1 };
        } else if (strcmp(sname, ".rela.dyn") == 0) {
            e.rela_dyn = (elf_sec_t){ s_addr, s_off, s_size, 1 };
        } else if (strcmp(sname, ".eh_frame_hdr") == 0) {
            e.eh_frame_hdr = (elf_sec_t){ s_addr, s_off, s_size, 1 };
        } else if (strcmp(sname, ".text") == 0) {
            e.text = (elf_sec_t){ s_addr, s_off, s_size, 1 };
        }
    }

    if (!e.rodata.found || !e.rela_dyn.found || !e.eh_frame_hdr.found || !e.text.found) {
        set_err(err, err_len, "missing required ELF sections (.rodata=%d .rela.dyn=%d .eh_frame_hdr=%d .text=%d)",
                e.rodata.found, e.rela_dyn.found, e.eh_frame_hdr.found, e.text.found);
        return -1;
    }

    if (init_starts(&e, err, err_len) != 0) {
        return -1;
    }

    uint64_t exp_strs[MAX_STR_HITS];
    size_t exp_str_count = find_str_in_rodata(&e, EXPERIMENT_STR, EXPERIMENT_LEN, exp_strs, MAX_STR_HITS);
    uint64_t row_strs[MAX_STR_HITS];
    size_t row_str_count = find_str_in_rodata(&e, DEVTOOLS_ROW_STR, DEVTOOLS_ROW_LEN, row_strs, MAX_STR_HITS);
    uint64_t env_strs[MAX_STR_HITS];
    size_t env_str_count = find_str_in_rodata(&e, DEV_ENV_STR, DEV_ENV_LEN, env_strs, MAX_STR_HITS);

    if (exp_str_count == 0 || row_str_count == 0 || env_str_count == 0) {
        free(e.sorted_starts);
        set_err(err, err_len, "anchor strings not found in .rodata (exp=%zu row=%zu env=%zu)",
                exp_str_count, row_str_count, env_str_count);
        return -1;
    }

    exp_slot_ctx_t slot_ctx;
    memset(&slot_ctx, 0, sizeof(slot_ctx));
    slot_ctx.e = &e;
    slot_ctx.exp_strs = exp_strs;
    slot_ctx.exp_str_count = exp_str_count;
    iterate_relocs(&e, visit_exp_slots, &slot_ctx);

    if (slot_ctx.slot_count == 0) {
        free(e.sorted_starts);
        set_err(err, err_len, "experiment table slot not found in .rela.dyn");
        return -1;
    }

    xref_collector_t xc;
    memset(&xc, 0, sizeof(xc));
    xc.exp_slots = slot_ctx.slots;
    xc.exp_slot_count = slot_ctx.slot_count;
    xc.row_strs = row_strs;
    xc.row_str_count = row_str_count;
    xc.env_strs = env_strs;
    xc.env_str_count = env_str_count;

    if (e.machine == PHOENIX_EM_AARCH64) {
        scan_xrefs_arm64(&e, &xc);
    } else {
        scan_xrefs_x86(&e, &xc);
    }

    /* Resolve access evaluator function start */
    uint64_t acc_hits[MAX_XREFS];
    size_t acc_hit_count = 0;
    for (size_t i = 0; i < xc.exp_xref_count; i++) {
        uint64_t f_start = 0, f_end = 0;
        func_bounds(&e, xc.exp_xrefs[i], &f_start, &f_end);
        acc_hits[acc_hit_count++] = f_start;
    }
    acc_hit_count = unique_u64(acc_hits, acc_hit_count);
    if (acc_hit_count != 1) {
        free(e.sorted_starts);
        set_err(err, err_len, "access evaluator: expected 1 match, got %zu", acc_hit_count);
        return -1;
    }

    uint64_t acc_va = acc_hits[0];
    size_t acc_off = 0;
    if (va_to_off(&e, acc_va, PHOENIX_EXPECT_LEN, &acc_off) != 0) {
        free(e.sorted_starts);
        set_err(err, err_len, "access evaluator VA 0x%llx unmapped", (unsigned long long)acc_va);
        return -1;
    }

    out->magic = PHOENIX_PLAN_MAGIC;
    out->version = PHOENIX_PLAN_VERSION;
    out->machine = e.machine;
    out->access_va = acc_va;
    out->access_exp_len = PHOENIX_EXPECT_LEN;
    memcpy(out->access_expect, data + acc_off, PHOENIX_EXPECT_LEN);

    if (e.machine == PHOENIX_EM_AARCH64) {
        static const uint32_t arm64_ret_true[2] = { 0x52800020u, 0xd65f03c0u }; /* mov w0,#1; ret */
        out->access_len = sizeof(arm64_ret_true);
        memcpy(out->access_code, arm64_ret_true, sizeof(arm64_ret_true));
    } else {
        static const uint8_t x86_ret_true[3] = { 0xb0, 0x01, 0xc3 }; /* mov al,1; ret */
        out->access_len = sizeof(x86_ret_true);
        memcpy(out->access_code, x86_ret_true, sizeof(x86_ret_true));
    }

    int rc;
    if (e.machine == PHOENIX_EM_AARCH64) {
        rc = resolve_arm64_is_staff(&e, &xc, out, err, err_len);
    } else {
        rc = resolve_x86_is_staff(&e, &xc, out, err, err_len);
    }

    free(e.sorted_starts);
    return rc;
}
