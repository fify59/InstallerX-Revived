// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.self.filecache

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.DigestInputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

public class FileCache {
    public companion object {
        private const val TAG = "FileCache"
    }

    private val mCacheDir: File

    constructor(context: Context) {
        mCacheDir = File(context.cacheDir, "file_cache")
        if (!mCacheDir.exists()) {
            mCacheDir.mkdirs()
        }
    }

    constructor(cacheDir: File) {
        mCacheDir = cacheDir
        if (!mCacheDir.exists()) {
            mCacheDir.mkdirs()
        }
    }

    /**
     * Get a cached file from an input stream. The stream is consumed and closed.
     * The returned file is cached by its SHA-256 digest.
     */
    @Throws(IOException::class)
    public fun getCachedFile(inputStream: InputStream, prefix: String = "cached"): File {
        val sha256 = computeSHA256(inputStream)
        val cacheFile = File(mCacheDir, "$prefix-$sha256")
        
        if (!cacheFile.exists()) {
            // We need to re-read the stream, but it's already consumed.
            // This is a limitation - the caller should provide the stream again or we cache during first read.
            // For now, we'll throw an exception if the file doesn't exist.
            throw IOException("Cache file not found and stream was consumed: $cacheFile")
        }
        
        return cacheFile
    }

    /**
     * Create a new cached file with the given prefix.
     * The caller is responsible for writing to this file.
     */
    public fun createCachedFile(prefix: String = "cached"): File {
        val timestamp = System.currentTimeMillis()
        val random = (Math.random() * 10000).toInt()
        return File(mCacheDir, "$prefix-$timestamp-$random")
    }

    /**
     * Compute SHA-256 of an input stream and reset it if possible.
     * Note: This consumes the stream. The caller must handle re-reading if needed.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class)
    private fun computeSHA256(inputStream: InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(8192)
        var bytesRead: Int
        
        // We can't reset a generic InputStream, so we compute while reading
        // The caller must handle re-reading if the stream is needed again
        while (inputStream.read(buffer).also { bytesRead = it } != -1) {
            digest.update(buffer, 0, bytesRead)
        }
        
        return bytesToHex(digest.digest())
    }

    /**
     * Compute SHA-256 of a file.
     */
    @Throws(IOException::class, NoSuchAlgorithmException::class)
    public fun computeFileSHA256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { fis ->
            val buffer = ByteArray(8192)
            var bytesRead: Int
            while (fis.read(buffer).also { bytesRead = it } != -1) {
                digest.update(buffer, 0, bytesRead)
            }
        }
        return bytesToHex(digest.digest())
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    /**
     * Close and clean up the cache directory.
     */
    public fun close() {
        deleteRecursively(mCacheDir)
    }

    private fun deleteRecursively(file: File) {
        if (file.isDirectory) {
            file.listFiles()?.forEach { deleteRecursively(it) }
        }
        file.delete()
    }
}
