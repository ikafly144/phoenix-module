package io.github.ikafly144.phoenix.xposed

import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ZipEntryLocatorTest {
    @Test
    fun `locates stored and deflated entries with exact raw offset`() {
        val tempDir = Files.createTempDirectory("phoenix-zip-test").toFile()
        try {
            val zipFile = File(tempDir, "test.apk")
            val storedPayload = ByteArray(4096) { i -> ((i * 31 + 7) and 0xff).toByte() }
            val deflatedPayload = "deflated-content-".repeat(100).encodeToByteArray()

            ZipOutputStream(zipFile.outputStream()).use { zos ->
                // Entry 1: DEFLATED
                val e1 = ZipEntry("classes.dex").apply {
                    method = ZipEntry.DEFLATED
                }
                zos.putNextEntry(e1)
                zos.write(deflatedPayload)
                zos.closeEntry()

                // Entry 2: STORED
                val crc = CRC32().apply { update(storedPayload) }.value
                val e2 = ZipEntry("lib/arm64-v8a/${PhoenixConstants.DISCORD_HOST_SO}").apply {
                    method = ZipEntry.STORED
                    size = storedPayload.size.toLong()
                    compressedSize = storedPayload.size.toLong()
                    this.crc = crc
                    extra = ByteArray(12) { 0x42 }
                }
                zos.putNextEntry(e2)
                zos.write(storedPayload)
                zos.closeEntry()
            }

            val storedLoc = ZipEntryLocator.locate(zipFile, "lib/arm64-v8a/${PhoenixConstants.DISCORD_HOST_SO}")
            assertNotNull(storedLoc)
            assertTrue(storedLoc.isStored)
            assertEquals(storedPayload.size.toLong(), storedLoc.uncompressedSize)

            val slice = ByteArray(storedLoc.uncompressedSize.toInt())
            RandomAccessFile(zipFile, "r").use { raf ->
                raf.seek(storedLoc.dataOffset)
                raf.readFully(slice)
            }
            assertContentEquals(storedPayload, slice)

            val deflatedLoc = ZipEntryLocator.locate(zipFile, "classes.dex")
            assertNotNull(deflatedLoc)
            assertFalse(deflatedLoc.isStored)
            assertEquals(deflatedPayload.size.toLong(), deflatedLoc.uncompressedSize)

            assertNull(ZipEntryLocator.locate(zipFile, "lib/x86_64/nonexistent.so"))
        } finally {
            tempDir.deleteRecursively()
        }
    }
}
