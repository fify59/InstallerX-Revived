// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.apk.signing

import android.content.Context
import android.os.Build
import android.util.Log
import androidx.annotation.NonNull
import androidx.annotation.Nullable
import androidx.annotation.WorkerThread
import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import com.rosan.installer.crypto.ks.KeyStoreManager
import com.rosan.installer.self.filecache.FileCache
import com.rosan.installer.util.DigestUtils
import com.rosan.installer.util.Utils
import java.io.File
import java.io.IOException
import java.security.KeyStoreException
import java.security.PrivateKey
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.security.interfaces.DSAKey
import java.security.interfaces.ECKey
import java.security.interfaces.RSAKey
import java.util.Collections

public class Signer {
    public companion object {
        const val TAG = "Signer"
        const val SIGNING_KEY_ALIAS = "signing_key"

        public fun canSign(context: Context): Boolean = try {
            KeyStoreManager.getInstance(context).containsKey(SIGNING_KEY_ALIAS)
        } catch (e: Exception) {
            false
        }

        public data class SignedApk(
            @NonNull public val apk: File,
            @Nullable public val idsig: File?,
        )

        @WorkerThread
        @NonNull
        public fun signCopy(
            context: Context,
            @NonNull `in`: File,
            @NonNull cache: FileCache,
            sigSchemes: SigSchemes,
            zipAlign: Boolean,
        ): SignedApk {
            val out = cache.createCachedFile("apk")
            try {
                val signer = getInstance(context, sigSchemes)
                var idsig: File? = null
                if (signer.isV4SchemeEnabled()) {
                    idsig = cache.createCachedFile("idsig")
                    signer.setIdsigFile(idsig)
                }
                if (signer.sign(`in`, out, -1, zipAlign) && verify(sigSchemes, out, idsig)) {
                    return SignedApk(out, idsig)
                }
                throw IOException("Failed to sign $`in`")
            } catch (e: SignatureException) {
                throw IOException(e)
            } catch (e: RuntimeException) {
                throw IOException(e)
            }
        }

        @NonNull
        private fun getInstance(context: Context, sigSchemes: SigSchemes): Signer {
            try {
                val manager = KeyStoreManager.getInstance(context)
                val signingKey = manager.getKeyPair(SIGNING_KEY_ALIAS)
                    ?: throw KeyStoreException("Alias $SIGNING_KEY_ALIAS does not exist in KeyStore.")
                return Signer(sigSchemes, signingKey.privateKey, signingKey.x509Certificate)
            } catch (e: Exception) {
                throw SignatureException(e)
            }
        }

        public fun verify(@NonNull sigSchemes: SigSchemes, @NonNull apk: File, @Nullable idsig: File?): Boolean {
            val builder = ApkVerifier.Builder(apk)
                .setMaxCheckedPlatformVersion(Build.VERSION.SDK_INT)
            if (sigSchemes.v4SchemeEnabled()) {
                if (idsig == null) {
                    throw RuntimeException("idsig file is mandatory for v4 signature scheme.")
                }
                builder.setV4SignatureFile(idsig)
            }
            val verifier = builder.build()
            return try {
                val result = verifier.verify()
                Log.i(TAG, "$apk")
                val isVerify = result.isVerified

                if (isVerify) {
                    if (sigSchemes.v1SchemeEnabled() && result.isVerifiedUsingV1Scheme()) {
                        Log.i(TAG, "V1 signature verified.")
                    } else {
                        Log.w(TAG, "V1 signature verification failed/disabled.")
                    }
                    if (sigSchemes.v2SchemeEnabled() && result.isVerifiedUsingV2Scheme()) {
                        Log.i(TAG, "V2 signature verified.")
                    } else {
                        Log.w(TAG, "V2 signature verification failed/disabled.")
                    }
                    if (sigSchemes.v3SchemeEnabled()) {
                        if (result.isVerifiedUsingV3Scheme()) {
                            Log.i(TAG, "V3 signature verified.")
                        } else {
                            Log.w(TAG, "V3 signature verification failed.")
                        }
                        if (result.isVerifiedUsingV31Scheme()) {
                            Log.i(TAG, "V3.1 signature verified.")
                        } else {
                            Log.w(TAG, "V3.1 signature verification failed.")
                        }
                    } else {
                        Log.w(TAG, "V3 signature verification disabled.")
                    }
                    if (sigSchemes.v4SchemeEnabled() && result.isVerifiedUsingV4Scheme()) {
                        Log.i(TAG, "V4 signature verified.")
                    } else {
                        Log.w(TAG, "V4 signature verification failed/disabled.")
                    }
                    if (result.isSourceStampVerified()) {
                        Log.i(TAG, "SourceStamp verified.")
                    } else {
                        Log.w(TAG, "SourceStamp not verified/unavailable.")
                    }

                    var i = 0
                    Log.i(TAG, "Number of signatures: ${result.signerCertificates.size}")
                    for (certificate in result.signerCertificates) {
                        i++
                        logCert(certificate, "Signature$i")
                    }
                }
                for (warn in result.warnings) Log.w(TAG, "$warn")
                for (err in result.errors) Log.e(TAG, "$err")
                if (sigSchemes.v1SchemeEnabled()) {
                    for (signer in result.v1SchemeIgnoredSigners) {
                        val name = signer.name
                        for (err in signer.errors) Log.e(TAG, "$name: $err")
                        for (warn in signer.warnings) Log.w(TAG, "$name: $warn")
                    }
                }
                isVerify
            } catch (e: Exception) {
                Log.w(TAG, "Verification failed.", e)
                false
            }
        }

        private fun logCert(@NonNull certificate: X509Certificate, charSequence: CharSequence) {
            val bitLength = when (val publicKey = certificate.publicKey) {
                is RSAKey -> publicKey.modulus.bitLength()
                is ECKey -> publicKey.params.order.bitLength()
                is DSAKey -> publicKey.params?.p?.bitLength() ?: -1
                else -> -1
            }
            Log.i(TAG, "$charSequence - Unique distinguished name: ${certificate.subjectDN}")
            logEncoded(charSequence, certificate.encoded)
            Log.i(TAG, "$charSequence - key size: ${if (bitLength != -1) bitLength.toString() else "Unknown"}")
            val algorithm = certificate.publicKey.algorithm
            Log.i(TAG, "$charSequence - key algorithm: ${Utils.prettifyKeyAlgorithmName(algorithm)}")
            logEncoded(charSequence, certificate.publicKey.encoded)
        }

        private fun logEncoded(charSequence: CharSequence, bytes: ByteArray) {
            log(charSequence.toString() + " - SHA-256: ", DigestUtils.getDigest(DigestUtils.SHA_256, bytes))
            log(charSequence.toString() + " - SHA-1: ", DigestUtils.getDigest(DigestUtils.SHA_1, bytes))
            log(charSequence.toString() + " - MD5: ", DigestUtils.getDigest(DigestUtils.MD5, bytes))
        }

        private fun log(str: String, bytes: ByteArray) {
            Log.i(TAG, str)
            Log.w(TAG, bytesToHex(bytes))
        }

        private fun bytesToHex(bytes: ByteArray): String {
            val sb = StringBuilder(bytes.size * 2)
            for (b in bytes) sb.append(String.format("%02x", b))
            return sb.toString()
        }
    }

    @NonNull
    private val mPrivateKey: PrivateKey

    @NonNull
    private val mCertificate: X509Certificate

    @NonNull
    private val mSigSchemes: SigSchemes

    @Nullable
    private var mIdsigFile: File? = null

    private constructor(
        @NonNull sigSchemes: SigSchemes,
        @NonNull privateKey: PrivateKey,
        @NonNull certificate: X509Certificate,
    ) {
        mSigSchemes = sigSchemes
        mPrivateKey = privateKey
        mCertificate = certificate
    }

    public fun isV4SchemeEnabled(): Boolean = mSigSchemes.v4SchemeEnabled()

    public fun setIdsigFile(@Nullable idsigFile: File?) {
        mIdsigFile = idsigFile
    }

    @WorkerThread
    public fun sign(
        @NonNull `in`: File,
        @NonNull out: File,
        minSdk: Int,
        alignFileSize: Boolean,
    ): Boolean {
        val signerConfig = ApkSigner.SignerConfig.Builder(
            "CERT",
            mPrivateKey,
            Collections.singletonList(mCertificate),
        ).build()
        val builder = ApkSigner.Builder(Collections.singletonList(signerConfig))
        builder.setInputApk(`in`)
        builder.setOutputApk(out)
        builder.setCreatedBy("InstallerX")
        builder.setAlignFileSize(alignFileSize)
        if (minSdk != -1) builder.setMinSdkVersion(minSdk)
        builder.setV1SigningEnabled(mSigSchemes.v1SchemeEnabled())
        builder.setV2SigningEnabled(mSigSchemes.v2SchemeEnabled())
        builder.setV3SigningEnabled(mSigSchemes.v3SchemeEnabled())
        if (mSigSchemes.v4SchemeEnabled()) {
            if (mIdsigFile == null) throw RuntimeException("idsig file is mandatory for v4 signature scheme.")
            builder.setV4SigningEnabled(true)
            builder.setV4SignatureOutputFile(mIdsigFile)
        } else {
            builder.setV4SigningEnabled(false)
        }
        val signer = builder.build()
        Log.i(TAG, "SignApk: $`in`")
        return try {
            if (alignFileSize && !ZipAlign.verify(`in`, ZipAlign.ALIGNMENT_4, true)) {
                ZipAlign.align(`in`, ZipAlign.ALIGNMENT_4, true)
            }
            signer.sign()
            Log.i(TAG, "The signature is complete and the output file is $out")
            true
        } catch (e: Exception) {
            Log.w(TAG, e)
            false
        }
    }
}
