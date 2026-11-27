// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.util

public object Utils {
    /**
     * Prettify the key algorithm name for display.
     */
    public fun prettifyKeyAlgorithmName(algorithm: String): String = when (algorithm.uppercase()) {
        "RSA" -> "RSA"
        "DSA" -> "DSA"
        "EC" -> "EC"
        "ECDSA" -> "ECDSA"
        "EDDSA" -> "EdDSA"
        "XDH" -> "XDH"
        "X25519" -> "X25519"
        "X448" -> "X448"
        else -> algorithm
    }
}
