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
        if (mPrivateKey is java.security.interfaces.DSADestroyable) {
            (mPrivateKey as java.security.interfaces.DSADestroyable).destroy()
        } else if (mPrivateKey is java.security.interfaces.RSADestroyable) {
            (mPrivateKey as java.security.interfaces.RSADestroyable).destroy()
        } else if (mPrivateKey is java.security.interfaces.ECDestroyable) {
            (mPrivateKey as java.security.interfaces.ECDestroyable).destroy()
        }
    }
}
