package io.github.ikafly144.phoenix.xposed

import io.github.ikafly144.phoenix.xposed.tweaks.STAFF_SETTINGS_PRELOAD_JS
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PhoenixPatchVerificationTest {
    @Test
    fun `staff settings preload js contains required hooks`() {
        assertTrue(STAFF_SETTINGS_PRELOAD_JS.contains("isStaffEnv"))
        assertTrue(STAFF_SETTINGS_PRELOAD_JS.contains("DeveloperExperimentStore"))
        assertTrue(STAFF_SETTINGS_PRELOAD_JS.contains("UserStore"))
        assertTrue(STAFF_SETTINGS_PRELOAD_JS.contains("isDeveloper"))
        assertTrue(STAFF_SETTINGS_PRELOAD_JS.contains("__d"))
    }

    @Test
    fun `native phoenix_elf resolver finds anchors and generates hooks for arm64 and x86_64`() {
        val cc = listOf("cc", "gcc", "clang").firstOrNull { cmd ->
            runCatching {
                ProcessBuilder(cmd, "--version").start().waitFor() == 0
            }.getOrDefault(false)
        } ?: return

        val tempDir = Files.createTempDirectory("phoenix-elf-test").toFile()
        try {
            val cppDir = File("src/main/cpp").takeIf { it.isDirectory }
                ?: File("app/src/main/cpp")
            assertTrue(cppDir.isDirectory, "Cannot locate src/main/cpp directory")

            val arm64Elf = File(tempDir, "mock_arm64.so").apply {
                writeBytes(buildMockElf64(isArm64 = true))
            }
            val x86Elf = File(tempDir, "mock_x86_64.so").apply {
                writeBytes(buildMockElf64(isArm64 = false))
            }

            val harnessC = File(tempDir, "harness.c")
            harnessC.writeText(
                """
                #include <stdio.h>
                #include <stdlib.h>
                #include <string.h>
                #include "phoenix_elf.h"

                static int check_file(const char *path, uint32_t expected_machine) {
                    FILE *fp = fopen(path, "rb");
                    if (!fp) { fprintf(stderr, "cannot open %s\n", path); return 1; }
                    fseek(fp, 0, SEEK_END);
                    long sz = ftell(fp);
                    fseek(fp, 0, SEEK_SET);
                    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
                    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) return 1;
                    fclose(fp);

                    phoenix_patch_plan_t plan;
                    char err[256] = {0};
                    if (phoenix_resolve_elf(buf, (size_t)sz, &plan, err, sizeof(err)) != 0) {
                        fprintf(stderr, "resolve failed for %s: %s\n", path, err);
                        free(buf);
                        return 2;
                    }
                    free(buf);

                    if (plan.magic != PHOENIX_PLAN_MAGIC || plan.machine != expected_machine) return 3;
                    if (plan.access_va != 0x1100ULL) {
                        fprintf(stderr, "unexpected access_va: 0x%llx\n", (unsigned long long)plan.access_va);
                        return 4;
                    }
                    if (plan.staff_va != 0x1300ULL) {
                        fprintf(stderr, "unexpected staff_va: 0x%llx\n", (unsigned long long)plan.staff_va);
                        return 5;
                    }
                    if (plan.staff_tag_off != 0x8580u || plan.staff_val_off != 0x8588u) {
                        fprintf(stderr, "unexpected tag/val: 0x%x / 0x%x\n", plan.staff_tag_off, plan.staff_val_off);
                        return 6;
                    }
                    printf("OK machine=%u access=0x%llx(%u) staff=0x%llx(%u) key=0x%llx tag=0x%x val=0x%x\n",
                           plan.machine,
                           (unsigned long long)plan.access_va, plan.access_len,
                           (unsigned long long)plan.staff_va, plan.staff_len,
                           (unsigned long long)plan.staff_key,
                           plan.staff_tag_off, plan.staff_val_off);
                    return 0;
                }

                int main(int argc, char **argv) {
                    if (argc < 3) return 1;
                    if (check_file(argv[1], PHOENIX_EM_AARCH64) != 0) return 10;
                    if (check_file(argv[2], PHOENIX_EM_X86_64) != 0) return 20;
                    return 0;
                }
                """.trimIndent()
            )

            val bin = File(tempDir, "harness")
            val compileProc = ProcessBuilder(
                cc,
                "-std=c11",
                "-O2",
                "-I${cppDir.absolutePath}",
                harnessC.absolutePath,
                File(cppDir, "phoenix_elf.c").absolutePath,
                "-o",
                bin.absolutePath,
            ).redirectErrorStream(true).start()
            val compileOut = compileProc.inputStream.bufferedReader().readText()
            assertEquals(0, compileProc.waitFor(), "C harness compilation failed:\n$compileOut")

            val runProc = ProcessBuilder(
                bin.absolutePath,
                arm64Elf.absolutePath,
                x86Elf.absolutePath,
            ).redirectErrorStream(true).start()
            val runOut = runProc.inputStream.bufferedReader().readText()
            assertEquals(0, runProc.waitFor(), "C harness execution failed:\n$runOut")
            assertTrue(runOut.contains("OK machine=183"))
            assertTrue(runOut.contains("OK machine=62"))
        } finally {
            tempDir.deleteRecursively()
        }
    }

    /**
     * Builds a synthetic ELF64 image with `.text`, `.rodata`, `.rela.dyn` (APS2), and `.eh_frame_hdr`
     * matching the exact anchor layout of `liblibdiscord_wasm_host.so`:
     * - `0x1000`: read_state
     * - `0x1040`: drop_guard
     * - `0x1100`: access evaluator (references experiment slot `0x3000`)
     * - `0x1200`: dev_analytics_env (references `"LIBDISCORD_DEV_ANALYTICS"` at `0x2040`)
     * - `0x1300`: is_staff (key `0x2080`, calls `0x1000` and `0x1040`, tag `+0x8580`, val `+0x8588`)
     * - `0x1400`: devtools_builder (calls `0x1200` then `0x1300`, references `"Show Dev Tools Widget"` at `0x2020`)
     */
    private fun buildMockElf64(isArm64: Boolean): ByteArray {
        val buf = ByteArray(0x5000)
        val bb = ByteBuffer.wrap(buf).order(ByteOrder.LITTLE_ENDIAN)

        // ELF64 header
        buf[0] = 0x7f; buf[1] = 'E'.code.toByte(); buf[2] = 'L'.code.toByte(); buf[3] = 'F'.code.toByte()
        buf[4] = 2 // ELFCLASS64
        buf[5] = 1 // ELFDATA2LSB
        buf[6] = 1 // EV_CURRENT
        bb.putShort(16, 3) // ET_DYN
        bb.putShort(18, if (isArm64) 183 else 62) // e_machine
        bb.putInt(20, 1)
        bb.putLong(32, 0x40L) // e_phoff
        bb.putLong(40, 0x4000L) // e_shoff
        bb.putShort(52, 64) // e_ehsize
        bb.putShort(54, 56) // e_phentsize
        bb.putShort(56, 1) // e_phnum
        bb.putShort(58, 64) // e_shentsize
        bb.putShort(60, 6) // e_shnum
        bb.putShort(62, 5) // e_shstrndx

        // Single PT_LOAD mapping 0x0..0x4000 with vaddr == offset
        bb.putInt(0x40, 1) // PT_LOAD
        bb.putInt(0x44, 5) // PF_R | PF_X
        bb.putLong(0x48, 0L) // p_offset
        bb.putLong(0x50, 0L) // p_vaddr
        bb.putLong(0x58, 0L) // p_paddr
        bb.putLong(0x60, 0x4000L) // p_filesz
        bb.putLong(0x68, 0x4000L) // p_memsz
        bb.putLong(0x70, 0x1000L) // p_align

        // .rodata at 0x2000
        fun putStr(off: Int, s: String) {
            val b = s.encodeToByteArray()
            System.arraycopy(b, 0, buf, off, b.size)
        }
        putStr(0x2000, "2026-11-phoenix-app-access")
        putStr(0x2020, "Show Dev Tools Widget")
        putStr(0x2040, "LIBDISCORD_DEV_ANALYTICS")
        putStr(0x2080, "UserStoreStateKey")

        // Experiment slot at 0x3000: { ptr = 0x2000, len = 26 }
        bb.putLong(0x3000, 0x2000L)
        bb.putLong(0x3008, 26L)

        // .rela.dyn at 0x3100 (APS2 format: 1 relocation at slot 0x3000 -> addend 0x2000)
        val aps2 = ByteArrayOutputStream().apply {
            write("APS2".encodeToByteArray())
            write(sleb(1)) // count = 1
            write(sleb(0x3000)) // initial roff = 0x3000
            write(sleb(1)) // gs = 1
            write(sleb(1 or 2 or 8)) // fl = GROUPED_BY_INFO | GROUPED_BY_OFFSET_DELTA | HAS_ADDEND
            write(sleb(0)) // god = 0
            write(sleb(if (isArm64) 1027 else 8)) // r_type
            write(sleb(0x2000)) // addend delta = 0x2000
        }.toByteArray()
        System.arraycopy(aps2, 0, buf, 0x3100, aps2.size)

        // .eh_frame_hdr at 0x3400
        val funcStarts = intArrayOf(0x1000, 0x1040, 0x1100, 0x1200, 0x1300, 0x1400, 0x1500)
        bb.putInt(0x3400 + 8, funcStarts.size)
        for ((idx, fs) in funcStarts.withIndex()) {
            bb.putInt(0x3400 + 12 + idx * 8, fs - 0x3400)
            bb.putInt(0x3400 + 16 + idx * 8, 0)
        }

        if (isArm64) {
            fun adrp(pc: Int, target: Int, rd: Int): Int {
                val imm = ((target ushr 12) - (pc ushr 12)) and 0x1fffff
                return 0x90000000.toInt() or ((imm and 3) shl 29) or ((imm ushr 2) shl 5) or rd
            }
            fun addImm12(rn: Int, rd: Int, imm12: Int): Int =
                0x91000000.toInt() or ((imm12 and 0xfff) shl 10) or (rn shl 5) or rd
            fun bl(pc: Int, target: Int): Int =
                0x94000000.toInt() or (((target - pc) shr 2) and 0x03ffffff)

            // 0x1000: read_state; 0x1040: drop
            bb.putInt(0x1000, 0xd65f03c0.toInt())
            bb.putInt(0x1040, 0xd65f03c0.toInt())

            // 0x1100: access evaluator referencing slot 0x3000
            bb.putInt(0x1100, adrp(0x1100, 0x3000, 0))
            bb.putInt(0x1104, addImm12(0, 0, 0))
            bb.putInt(0x1108, 0xd65f03c0.toInt())

            // 0x1200: dev_analytics_env referencing 0x2040 ("LIBDISCORD_DEV_ANALYTICS")
            bb.putInt(0x1200, adrp(0x1200, 0x2040, 0))
            bb.putInt(0x1204, addImm12(0, 0, 0x40))
            bb.putInt(0x1208, 0xd65f03c0.toInt())

            // 0x1300: is_staff (must be >= 88 bytes, here 0x1300..0x1400 = 256 bytes)
            var p = 0x1300
            bb.putInt(p, adrp(p, 0x2080, 1)); p += 4
            bb.putInt(p, addImm12(1, 1, 0x80)); p += 4
            bb.putInt(p, bl(p, 0x1000)); p += 4 // call 1: read_state
            // add x8, x8, #8, lsl #12 -> 0x91402108
            bb.putInt(p, 0x91400000.toInt() or (8 shl 10) or (8 shl 5) or 8); p += 4
            // ldr w9, [x8, #0x580] (imm12 = 0x580 / 4 = 0x160)
            bb.putInt(p, 0xb9400000.toInt() or (0x160 shl 10) or (8 shl 5) or 9); p += 4
            // ldr w10, [x8, #0x588] (imm12 = 0x588 / 4 = 0x162)
            bb.putInt(p, 0xb9400000.toInt() or (0x162 shl 10) or (8 shl 5) or 10); p += 4
            // cmp w9, #0 -> 0x7100013f
            bb.putInt(p, 0x7100001f or (9 shl 5)); p += 4
            // csel w11, w10, wzr, ne -> 0x1a9f114b
            bb.putInt(p, 0x1a9f1000 or (10 shl 5) or 11); p += 4
            bb.putInt(p, bl(p, 0x1040)); p += 4 // call 2: drop
            bb.putInt(p, 0xd65f03c0.toInt())

            // 0x1400: devtools_builder calls 0x1200, then 0x1300, then references 0x2020
            bb.putInt(0x1400, bl(0x1400, 0x1200))
            bb.putInt(0x1404, bl(0x1404, 0x1300))
            bb.putInt(0x1408, adrp(0x1408, 0x2020, 0))
            bb.putInt(0x140c, addImm12(0, 0, 0x20))
            bb.putInt(0x1410, 0xd65f03c0.toInt())
        } else {
            fun putLeaRip(pos: Int, rex: Int, modrm: Int, target: Int): Int {
                buf[pos] = rex.toByte()
                buf[pos + 1] = 0x8d.toByte()
                buf[pos + 2] = modrm.toByte()
                bb.putInt(pos + 3, target - (pos + 7))
                return pos + 7
            }
            fun putCallRel(pos: Int, target: Int): Int {
                buf[pos] = 0xe8.toByte()
                bb.putInt(pos + 1, target - (pos + 5))
                return pos + 5
            }

            buf[0x1000] = 0xc3.toByte()
            buf[0x1040] = 0xc3.toByte()

            // 0x1100: access evaluator referencing slot 0x3000
            var p = putLeaRip(0x1100, 0x48, 0x05, 0x3000)
            buf[p] = 0xc3.toByte()

            // 0x1200: dev_analytics_env referencing 0x2040
            p = putLeaRip(0x1200, 0x48, 0x05, 0x2040)
            buf[p] = 0xc3.toByte()

            // 0x1300: is_staff
            p = 0x1300
            p = putLeaRip(p, 0x48, 0x15, 0x2080) // lea rdx, [rip + KEY] (modrm 0x15 -> reg=2=rdx, rm=5)
            p = putCallRel(p, 0x1000) // call read_state
            // cmp byte ptr [rax + 0x8580], 0 -> 80 b8 80 85 00 00 00
            buf[p++] = 0x80.toByte(); buf[p++] = 0xb8.toByte()
            bb.putInt(p, 0x8580); p += 4
            buf[p++] = 0
            // mov esi, dword ptr [rax + 0x8588] -> 8b b0 88 85 00 00
            buf[p++] = 0x8b.toByte(); buf[p++] = 0xb0.toByte()
            bb.putInt(p, 0x8588); p += 4
            p = putCallRel(p, 0x1040) // call drop
            while (p < 0x13ff) buf[p++] = 0x90.toByte()
            buf[0x13ff] = 0xc3.toByte()

            // 0x1400: devtools_builder
            p = 0x1400
            p = putCallRel(p, 0x1200)
            p = putCallRel(p, 0x1300)
            p = putLeaRip(p, 0x48, 0x05, 0x2020)
            buf[p] = 0xc3.toByte()
        }

        // .shstrtab at 0x3800
        val shstr = "\u0000.text\u0000.rodata\u0000.rela.dyn\u0000.eh_frame_hdr\u0000.shstrtab\u0000".encodeToByteArray()
        System.arraycopy(shstr, 0, buf, 0x3800, shstr.size)

        fun writeShdr(idx: Int, nameOff: Int, type: Int, addr: Long, off: Long, size: Long) {
            val base = 0x4000 + idx * 64
            bb.putInt(base, nameOff)
            bb.putInt(base + 4, type)
            bb.putLong(base + 16, addr)
            bb.putLong(base + 24, off)
            bb.putLong(base + 32, size)
        }
        writeShdr(0, 0, 0, 0, 0, 0)
        writeShdr(1, 1, 1, 0x1000, 0x1000, 0x600) // .text
        writeShdr(2, 7, 1, 0x2000, 0x2000, 0x200) // .rodata
        writeShdr(3, 15, 4, 0x3100, 0x3100, aps2.size.toLong()) // .rela.dyn
        writeShdr(4, 25, 1, 0x3400, 0x3400, (12 + funcStarts.size * 8).toLong()) // .eh_frame_hdr
        writeShdr(5, 39, 3, 0x3800, 0x3800, shstr.size.toLong()) // .shstrtab

        return buf
    }

    private fun sleb(value: Long): ByteArray {
        val out = ByteArrayOutputStream()
        var v = value
        var more = true
        while (more) {
            var b = (v and 0x7f).toInt()
            v = v shr 7
            val signBit = (b and 0x40) != 0
            if ((v == 0L && !signBit) || (v == -1L && signBit)) {
                more = false
            } else {
                b = b or 0x80
            }
            out.write(b)
        }
        return out.toByteArray()
    }
}
