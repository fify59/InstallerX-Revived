// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

public class KeyPair(
    private val mPrivateKey: PrivateKey,
    private val mCertificate: Certificate,
) {
    public val privateKey: PrivateKey
        get() = mPrivateKey

    public val certificate: Certificate
        get() = mCertificate

    public val x509Certificate: X509Certificate
        get() = mCertificate as X509Certificate

    public fun destroy() {
        // Attempt to destroy private key if it supports Destroyable interface
        // Using reflection to handle API level differences
        try {
            val destroyableClass = Class.forName("java.security.Destroyable")
            if (destroyableClass.isInstance(mPrivateKey)) {
                destroyableClass.getMethod("destroy").invoke(mPrivateKey)
            }
        } catch (e: Exception) {
            // Ignore - Destroyable not available or destroy failed
        }
    }
}
