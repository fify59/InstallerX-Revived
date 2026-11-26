// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.util

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

public object DigestUtils {
    public const val SHA_256 = "SHA-256"
    public const val SHA_1 = "SHA-1"
    public const val MD5 = "MD5"

    /**
     * Get the digest of the given data using the specified algorithm.
     */
    public fun getDigest(algorithm: String, data: ByteArray): ByteArray {
        return try {
            MessageDigest.getInstance(algorithm).digest(data)
        } catch (e: NoSuchAlgorithmException) {
            throw RuntimeException("Algorithm $algorithm not available", e)
        }
    }

    /**
     * Get the hex digest of the given data using the specified algorithm.
     */
    public fun getHexDigest(algorithm: String, data: ByteArray): String {
        return bytesToHex(getDigest(algorithm, data))
    }

    private fun bytesToHex(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }
}
