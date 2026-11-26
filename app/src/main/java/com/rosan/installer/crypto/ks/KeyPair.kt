// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import java.security.PrivateKey
import java.security.cert.Certificate
import java.security.cert.X509Certificate

public class KeyPair(
    @Suppress("UNUSED_PARAMETER")
    private val privateKey: PrivateKey,
    @Suppress("UNUSED_PARAMETER")
    private val certificate: Certificate,
) {
    public val privateKey: PrivateKey
        get() = privateKey

    public val certificate: Certificate
        get() = certificate

    public val x509Certificate: X509Certificate
        get() = certificate as X509Certificate

    public fun destroy() {
        if (privateKey is java.security.interfaces.DSADestroyable) {
            (privateKey as java.security.interfaces.DSADestroyable).destroy()
        } else if (privateKey is java.security.interfaces.RSADestroyable) {
            (privateKey as java.security.interfaces.RSADestroyable).destroy()
        } else if (privateKey is java.security.interfaces.ECDestroyable) {
            (privateKey as java.security.interfaces.ECDestroyable).destroy()
        }
    }
}
