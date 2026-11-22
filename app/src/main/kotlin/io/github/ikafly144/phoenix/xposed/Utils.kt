package io.github.ikafly144.phoenix.xposed

import kotlinx.serialization.json.Json
import java.io.File
import java.io.RandomAccessFile

fun File.ensureDir() {
    if (!isDirectory) delete()
    mkdirs()
}

val PhoenixJson: Json = Json { ignoreUnknownKeys = true }

data class ZipEntryLocation(
    val zipFile: File,
    val entryName: String,
    val compressionMethod: Int,
    val dataOffset: Long,
    val uncompressedSize: Long,
) {
    val isStored: Boolean get() = compressionMethod == 0
}

/**
 * Locates an entry inside a ZIP/APK file by reading the Central Directory and Local File Header.
 * Avoids reflection on private Android `ZipEntry` fields and returns the exact raw byte offset
 * so uncompressed (`STORED`) `.so` entries can be `mmap`ed directly from the APK.
 */
object ZipEntryLocator {
    private const val EOCD_SIG = 0x06054b50
    private const val CEN_SIG = 0x02014b50
    private const val LOC_SIG = 0x04034b50

    fun locate(zipFile: File, targetEntryName: String): ZipEntryLocation? {
        if (!zipFile.isFile) return null
        RandomAccessFile(zipFile, "r").use { raf ->
            val fileLen = raf.length()
            if (fileLen < 22) return null

            val maxComment = 65535L
            val searchLen = minOf(fileLen, 22L + maxComment).toInt()
            val tail = ByteArray(searchLen)
            raf.seek(fileLen - searchLen)
            raf.readFully(tail)

            var eocdPos = -1
            for (i in searchLen - 22 downTo 0) {
                if (readLe32(tail, i) == EOCD_SIG) {
                    eocdPos = i
                    break
                }
            }
            if (eocdPos < 0) return null

            val cdSize = readLe32(tail, eocdPos + 12).toLong() and 0xffffffffL
            val cdOffset = readLe32(tail, eocdPos + 16).toLong() and 0xffffffffL
            if (cdOffset + cdSize > fileLen) return null

            val targetBytes = targetEntryName.encodeToByteArray()
            var pos = cdOffset
            val cdEnd = cdOffset + cdSize
            val headerBuf = ByteArray(46)

            while (pos + 46 <= cdEnd) {
                raf.seek(pos)
                raf.readFully(headerBuf)
                if (readLe32(headerBuf, 0) != CEN_SIG) return null

                val method = readLe16(headerBuf, 10)
                val uncompSize = readLe32(headerBuf, 24).toLong() and 0xffffffffL
                val nameLen = readLe16(headerBuf, 28)
                val extraLen = readLe16(headerBuf, 30)
                val commentLen = readLe16(headerBuf, 32)
                val locOffset = readLe32(headerBuf, 42).toLong() and 0xffffffffL

                if (nameLen == targetBytes.size) {
                    val nameBytes = ByteArray(nameLen)
                    raf.readFully(nameBytes)
                    if (nameBytes.contentEquals(targetBytes)) {
                        if (locOffset + 30 > fileLen) return null
                        val locBuf = ByteArray(30)
                        raf.seek(locOffset)
                        raf.readFully(locBuf)
                        if (readLe32(locBuf, 0) != LOC_SIG) return null
                        val locNameLen = readLe16(locBuf, 26)
                        val locExtraLen = readLe16(locBuf, 28)
                        val dataOffset = locOffset + 30L + locNameLen + locExtraLen
                        if (dataOffset > fileLen) return null
                        return ZipEntryLocation(
                            zipFile = zipFile,
                            entryName = targetEntryName,
                            compressionMethod = method,
                            dataOffset = dataOffset,
                            uncompressedSize = uncompSize,
                        )
                    }
                }

                pos += 46L + nameLen + extraLen + commentLen
            }
        }
        return null
    }

    private fun readLe16(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or ((b[off + 1].toInt() and 0xff) shl 8)

    private fun readLe32(b: ByteArray, off: Int): Int =
        (b[off].toInt() and 0xff) or
            ((b[off + 1].toInt() and 0xff) shl 8) or
            ((b[off + 2].toInt() and 0xff) shl 16) or
            ((b[off + 3].toInt() and 0xff) shl 24)
}

fun supportedTargetAbis(): List<String> =
    android.os.Build.SUPPORTED_ABIS?.filter { it == "arm64-v8a" || it == "x86_64" }?.takeIf { it.isNotEmpty() }
        ?: listOf("arm64-v8a", "x86_64")

fun extractZipEntry(
    zipFile: File,
    entryName: String,
    destFile: File,
    log: io.github.ikafly144.phoenix.Logger,
): Boolean =
    runCatching {
        java.util.zip.ZipFile(zipFile).use { zip ->
            val entry = zip.getEntry(entryName) ?: return false
            destFile.parentFile?.ensureDir()
            val tmp = File(destFile.path + ".tmp")
            zip.getInputStream(entry).use { input ->
                tmp.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            if (!tmp.renameTo(destFile)) {
                tmp.copyTo(destFile, overwrite = true)
                tmp.delete()
            }
            true
        }
    }.onFailure { e ->
        log.w("Failed extracting $entryName from ${zipFile.path}", e)
    }.getOrDefault(false)

fun loadModuleNativeLibrary(
    libName: String,
    modulePath: String,
    appInfo: android.content.pm.ApplicationInfo,
    log: io.github.ikafly144.phoenix.Logger,
): Boolean {
    if (runCatching { System.loadLibrary(libName) }.isSuccess) {
        log.i("Loaded lib$libName.so via System.loadLibrary")
        return true
    }

    val abis = supportedTargetAbis()
    for (abi in abis) {
        val directPath = "$modulePath!/lib/$abi/lib$libName.so"
        if (runCatching { System.load(directPath) }.isSuccess) {
            log.i("Loaded lib$libName.so directly from module APK ($abi)")
            return true
        }
    }

    val outDir = File(appInfo.dataDir, PhoenixConstants.CODE_CACHE_DIR).apply { ensureDir() }
    val outFile = File(outDir, "lib$libName.so")
    val moduleApk = File(modulePath)
    for (abi in abis) {
        val entryName = "lib/$abi/lib$libName.so"
        if (extractZipEntry(moduleApk, entryName, outFile, log)) {
            outFile.setReadable(true, true)
            outFile.setExecutable(true, true)
            if (runCatching { System.load(outFile.absolutePath) }
                    .onFailure { log.w("System.load(${outFile.absolutePath}) failed", it) }
                    .isSuccess
            ) {
                log.i("Extracted and loaded lib$libName.so ($abi)")
                return true
            }
        }
    }
    return false
}

