// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.Destroyable

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
        if (mPrivateKey is Destroyable) {
            (mPrivateKey as Destroyable).destroy()
        }
    }
}
