// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.SecretKey
import kotlin.jvm.Synchronized

public class KeyStoreManager {
    companion object {
        const val TAG = "KSManager"
        const val AM_KEYSTORE_FILE_NAME = "am_keystore.bks"
        const val AM_KEYSTORE = "BKS"
        const val PREF_AM_KEYSTORE_PREFIX = "ks_"
        public const val SIGNING_KEY_ALIAS = "signing_key"
        const val PREF_AM_KEYSTORE_PASS = "kspass"
        const val ACTION_KS_INTERACTION_BEGIN = "com.rosan.installer.x.revived.action.KS_INTERACTION_BEGIN"
        const val ACTION_KS_INTERACTION_END = "com.rosan.installer.x.revived.action.KS_INTERACTION_END"

        @SuppressLint("StaticFieldLeak")
        private var sInstance: KeyStoreManager? = null

        @Synchronized
        fun getInstance(context: Context): KeyStoreManager {
            if (sInstance == null) {
                sInstance = KeyStoreManager()
                sInstance!!.init(context.applicationContext)
            }
            return sInstance!!
        }

        @Synchronized
        fun reloadKeyStore() = sInstance = KeyStoreManager()

        @Synchronized
        fun clearCachedKeyStore() = sInstance = null
    }

    private var mContext: Context? = null
    private var mAmKeyStore: KeyStore? = null
    private var mInteractionWatcher: CountDownLatch? = null

    private var mKeyStoreFile: File? = null
    private var sSharedPreferences: SharedPreferences? = null

    constructor() {}

    private fun init(context: Context) {
        mContext = context
        mKeyStoreFile = File(context.filesDir, AM_KEYSTORE_FILE_NAME)
        sSharedPreferences = context.getSharedPreferences("keystore", Context.MODE_PRIVATE)
        mAmKeyStore = getAmKeyStore()
    }

    private fun getAmKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(AM_KEYSTORE)
        Log.w(TAG, "Using keystore $AM_KEYSTORE")
        val realPassword = getAmKeyStorePassword()
        try {
            mKeyStoreFile?.let { file ->
                if (file.exists()) {
                    val inputStream = FileInputStream(file)
                    try {
                        keyStore.load(inputStream, realPassword)
                    } finally {
                        inputStream.close()
                    }
                } else {
                    keyStore.load(null)
                }
            } ?: run { keyStore.load(null) }
        } finally {
            clearChars(realPassword)
        }
        return keyStore
    }

    @Throws(KeyStoreException::class)
    public fun getAmKeyStorePassword(): CharArray {
        val encryptedPass = sSharedPreferences?.getString(PREF_AM_KEYSTORE_PASS, null)
        if (encryptedPass == null) {
            return generateAndStoreNewPassword()
        }
        return try {
            decryptPassword(encryptedPass)
        } catch (e: Exception) {
            return generateAndStoreNewPassword()
        }
    }

    public fun hasSavedKeyStorePassword(): Boolean = sSharedPreferences?.contains(PREF_AM_KEYSTORE_PASS) ?: false

    public fun hasKeyStorePassword(): Boolean = try {
        reloadKeyStore()
        true
    } catch (e: Exception) {
        false
    }

    public fun hasKeyStore(): Boolean = mKeyStoreFile?.exists() ?: false

    @Throws(KeyStoreException::class)
    private fun generateAndStoreNewPassword(): CharArray {
        val password = generateRandomPassword()
        val encrypted = encryptPassword(password)
        sSharedPreferences?.edit().putString(PREF_AM_KEYSTORE_PASS, encrypted).apply()
        return password
    }

    private fun generateRandomPassword(): CharArray {
        val bytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP).toCharArray()
    }

    @Throws(KeyStoreException::class)
    private fun encryptPassword(password: CharArray): String =
        Base64.encodeToString(password.concatToString().toByteArray(StandardCharsets.UTF_8), Base64.NO_WRAP)

    @Throws(KeyStoreException::class, Exception::class)
    private fun decryptPassword(encryptedPass: String): CharArray =
        String(Base64.decode(encryptedPass, Base64.NO_WRAP), StandardCharsets.UTF_8).toCharArray()

    private fun clearChars(chars: CharArray) = java.util.Arrays.fill(chars, '\u0000')

    @Throws(KeyStoreException::class, CertificateException::class, IOException::class, NoSuchAlgorithmException::class)
    public fun insertKeyPair(alias: String, keyPair: KeyPair) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore?.setKeyEntry(alias, keyPair.privateKey, password, arrayOf(keyPair.certificate))
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    /**
     * Import a key pair from a PKCS12 (.p12/.pfx) file.
     * @param p12File The PKCS12 file to import
     * @param p12Password The password for the PKCS12 file
     * @param alias The alias to store the key under (default: "signing_key")
     * @return true if import was successful
     */
    @Throws(KeyStoreException::class, IOException::class, NoSuchAlgorithmException::class, CertificateException::class)
    public fun importKeyFromP12(
        p12File: File,
        p12Password: String,
        alias: String = SIGNING_KEY_ALIAS,
    ): Boolean {
        if (!p12File.exists()) {
            throw IOException("PKCS12 file not found: ${p12File.absolutePath}")
        }

        val p12Store = KeyStore.getInstance("PKCS12")
        val p12InputStream = FileInputStream(p12File)
        try {
            p12Store.load(p12InputStream, p12Password.toCharArray())
        } finally {
            p12InputStream.close()
        }

        var keyAlias: String? = null
        val aliases = p12Store.aliases()
        while (aliases.hasMoreElements()) {
            val a = aliases.nextElement()
            if (p12Store.isKeyEntry(a)) {
                keyAlias = a
                break
            }
        }

        if (keyAlias == null) {
            throw KeyStoreException("No private key found in PKCS12 file")
        }

        val privateKey = p12Store.getKey(keyAlias, p12Password.toCharArray()) as? PrivateKey
            ?: throw KeyStoreException("Failed to extract private key from PKCS12")

        val certChain = p12Store.getCertificateChain(keyAlias)
            ?: throw KeyStoreException("No certificate chain found in PKCS12")

        val keyPair = KeyPair(privateKey, certChain[0] as X509Certificate)
        insertKeyPairInternal(alias, keyPair)

        Log.i(TAG, "Successfully imported key from PKCS12 as '$alias'")
        return true
    }

    @Throws(KeyStoreException::class, CertificateException::class, IOException::class, NoSuchAlgorithmException::class)
    private fun insertKeyPairInternal(alias: String, keyPair: KeyPair) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore?.setKeyEntry(alias, keyPair.privateKey, password, arrayOf(keyPair.certificate))
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    public fun containsKey(alias: String): Boolean = try {
        mAmKeyStore?.containsAlias(alias) ?: false
    } catch (e: KeyStoreException) {
        false
    }

    @Throws(KeyStoreException::class)
    public fun getKeyPair(alias: String): KeyPair? {
        val key = getKey(alias)
        if (key is PrivateKey) {
            return KeyPair(key, mAmKeyStore?.getCertificate(alias)!!)
        }
        throw KeyStoreException("The alias $alias does not have a KeyPair.")
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
    private fun getKey(alias: String): Key? {
        val password = getAmKeyStorePassword()
        val key = mAmKeyStore?.getKey(alias, password)
        clearChars(password)
        return key
    }

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun saveKeyStore(password: CharArray) {
        val os = FileOutputStream(mKeyStoreFile!!)
        try {
            mAmKeyStore?.store(os, password)
        } finally {
            os.close()
        }
    }

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    public fun removeKey(alias: String) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore?.deleteEntry(alias)
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    public fun getAliases(): List<String> = try {
        mAmKeyStore?.aliases()?.asSequence()?.toList() ?: emptyList()
    } catch (e: KeyStoreException) {
        emptyList()
    }

    private object ContextUtils {
        @Suppress("UNUSED_PARAMETER")
        fun getContext(): Context = throw UnsupportedOperationException("Need ContextUtils implementation")
    }
}
