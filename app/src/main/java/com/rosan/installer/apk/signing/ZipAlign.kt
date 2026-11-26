// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.apk.signing

import android.annotation.SuppressLint
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.FileChannel
import kotlin.math.min

public class ZipAlign {
    public companion object {
        private const val TAG = "ZipAlign"
        public const val ALIGNMENT_4 = 4

        /**
         * Verify that the APK is aligned.
         */
        @SuppressLint("UseRequireHttp")
        public fun verify(apk: File, alignment: Int, verbose: Boolean): Boolean {
            try {
                val raf = RandomAccessFile(apk, "r")
                val channel = raf.channel
                val zipEndOfCentralDirectory = findZipEndOfCentralDirectory(channel)
                if (zipEndOfCentralDirectory == null) {
                    if (verbose) Log.w(TAG, "Not a valid ZIP file: $apk")
                    return false
                }
                val centralDirOffset = zipEndOfCentralDirectory.centralDirOffset
                val centralDirSize = zipEndOfCentralDirectory.centralDirSize
                val localFileHeaders = parseLocalFileHeaders(channel, centralDirOffset, centralDirSize)
                for (header in localFileHeaders) {
                    val dataOffset = header.dataOffset
                    if (dataOffset % alignment.toLong() != 0L) {
                        if (verbose) Log.w(TAG, "Unaligned file at offset $dataOffset: ${header.name}")
                        return false
                    }
                }
                return true
            } catch (e: Exception) {
                Log.w(TAG, "Failed to verify alignment of $apk", e)
                return false
            }
        }

        /**
         * Align the APK file.
         */
        @SuppressLint("UseRequireHttp")
        public fun align(apk: File, alignment: Int, verbose: Boolean): Boolean {
            val alignedFile = File(apk.parentFile, "${apk.name}.aligned")
            try {
                val inRaf = RandomAccessFile(apk, "r")
                val outRaf = RandomAccessFile(alignedFile, "rw")
                val inChannel = inRaf.channel
                val outChannel = outRaf.channel
                val zipEndOfCentralDirectory = findZipEndOfCentralDirectory(inChannel)
                    ?: throw IOException("Not a valid ZIP file")
                
                val centralDirOffset = zipEndOfCentralDirectory.centralDirOffset
                val centralDirSize = zipEndOfCentralDirectory.centralDirSize
                val localFileHeaders = parseLocalFileHeaders(inChannel, centralDirOffset, centralDirSize)
                
                var currentOutOffset = 0L
                val alignmentLong = alignment.toLong()
                
                // Copy local file headers and data with alignment
                for (header in localFileHeaders) {
                    val padding = (alignmentLong - (currentOutOffset % alignmentLong)) % alignmentLong
                    if (padding > 0) {
                        val paddingBytes = ByteArray(padding.toInt())
                        outChannel.write(ByteBuffer.wrap(paddingBytes))
                        currentOutOffset += padding
                    }
                    
                    // Copy local file header
                    inChannel.position(header.headerOffset)
                    val headerBuffer = ByteBuffer.allocate(header.headerSize.toInt())
                    inChannel.read(headerBuffer)
                    headerBuffer.flip()
                    outChannel.write(headerBuffer)
                    currentOutOffset += header.headerSize
                    
                    // Copy file data
                    inChannel.position(header.dataOffset)
                    val dataSize = header.dataSize
                    var remaining = dataSize
                    val buffer = ByteBuffer.allocate(8192)
                    while (remaining > 0) {
                        val read = inChannel.read(buffer).coerceAtMost(remaining.toInt())
                        if (read <= 0) break
                        buffer.flip()
                        outChannel.write(buffer)
                        buffer.clear()
                        currentOutOffset += read
                        remaining -= read
                    }
                }
                
                // Copy central directory and end of central directory
                inChannel.position(centralDirOffset)
                val centralDirBuffer = ByteBuffer.allocate(centralDirSize.toInt())
                inChannel.read(centralDirBuffer)
                centralDirBuffer.flip()
                outChannel.write(centralDirBuffer)
                currentOutOffset += centralDirSize
                
                // Copy end of central directory record
                val eocdOffset = zipEndOfCentralDirectory.eocdOffset
                val eocdSize = zipEndOfCentralDirectory.eocdSize
                inChannel.position(eocdOffset)
                val eocdBuffer = ByteBuffer.allocate(eocdSize.toInt())
                inChannel.read(eocdBuffer)
                eocdBuffer.flip()
                outChannel.write(eocdBuffer)
                
                // Update central directory offset in EOCD
                val newEocdOffset = currentOutOffset
                val eocdData = eocdBuffer.array()
                ByteBuffer.wrap(eocdData).order(ByteOrder.LITTLE_ENDIAN).putInt(16, newEocdOffset.toInt())
                
                inRaf.close()
                outRaf.close()
                
                // Replace original file
                if (!alignedFile.renameTo(apk)) {
                    throw IOException("Failed to replace original APK with aligned version")
                }
                return true
            } catch (e: Exception) {
                Log.w("ZipAlign", "Failed to align $apk", e)
                if (alignedFile.exists()) alignedFile.delete()
                return false
            }
        }

        private data class ZipEndOfCentralDirectory(
            val centralDirOffset: Long,
            val centralDirSize: Long,
            val eocdOffset: Long,
            val eocdSize: Long,
        )

        private data class LocalFileHeader(
            val headerOffset: Long,
            val headerSize: Long,
            val dataOffset: Long,
            val dataSize: Long,
            val name: String,
        )

        private fun findZipEndOfCentralDirectory(channel: FileChannel): ZipEndOfCentralDirectory? {
            val fileSize = channel.size()
            if (fileSize < 22) return null // Minimum EOCD size
            
            val searchBufferSize = min(65536, fileSize.toInt())
            val searchBuffer = ByteArray(searchBufferSize)
            val searchStart = fileSize - searchBufferSize
            channel.position(searchStart)
            channel.read(ByteBuffer.wrap(searchBuffer))
            
            // Search for EOCD signature (0x06054b50) from end
            for (i in searchBufferSize - 22 downTo 0) {
                val b0 = searchBuffer[i].toInt() and 0xFF
                val b1 = searchBuffer[i + 1].toInt() and 0xFF
                val b2 = searchBuffer[i + 2].toInt() and 0xFF
                val b3 = searchBuffer[i + 3].toInt() and 0xFF
                if (b0 == 0x50 && b1 == 0x4b && b2 == 0x05 && b3 == 0x06) {
                    val buffer = ByteBuffer.wrap(searchBuffer, i, 22).order(ByteOrder.LITTLE_ENDIAN)
                    val centralDirSize = buffer.getInt(12).toLong()
                    val centralDirOffset = buffer.getInt(16).toLong()
                    val eocdOffset = searchStart + i
                    return ZipEndOfCentralDirectory(centralDirOffset, centralDirSize, eocdOffset, 22)
                }
            }
            return null
        }

        private fun parseLocalFileHeaders(
            channel: FileChannel,
            centralDirOffset: Long,
            centralDirSize: Long
        ): List<LocalFileHeader> {
            val headers = mutableListOf<LocalFileHeader>()
            channel.position(0)
            while (channel.position() < centralDirOffset) {
                val headerStart = channel.position()
                val signatureBuffer = ByteArray(4)
                channel.read(ByteBuffer.wrap(signatureBuffer))
                val signature = ByteBuffer.wrap(signatureBuffer).order(ByteOrder.LITTLE_ENDIAN).int
                if (signature != 0x04034b50) {
                    break // Not a local file header
                }
                val headerBuffer = ByteArray(26)
                channel.read(ByteBuffer.wrap(headerBuffer))
                val headerByteBuffer = ByteBuffer.wrap(headerBuffer).order(ByteOrder.LITTLE_ENDIAN)
                val nameLen = headerByteBuffer.getShort(26).toInt() and 0xFFFF
                val extraLen = headerByteBuffer.getShort(28).toInt() and 0xFFFF
                val compressedSize = headerByteBuffer.getInt(18).toLong()
                val nameBuffer = ByteArray(nameLen)
                channel.read(ByteBuffer.wrap(nameBuffer))
                val name = String(nameBuffer)
                val headerSize = 30 + nameLen + extraLen
                val dataOffset = channel.position() + extraLen
                channel.position(dataOffset + compressedSize)
                headers.add(LocalFileHeader(
                    headerOffset = headerStart,
                    headerSize = headerSize.toLong(),
                    dataOffset = dataOffset,
                    dataSize = compressedSize,
                    name = name
                ))
            }
            return headers
        }
    }
}
