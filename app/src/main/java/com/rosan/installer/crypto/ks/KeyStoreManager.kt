// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.security.Key
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.UnrecoverableKeyException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate

class KeyStoreManager private constructor(context: Context) {
    companion object {
        const val TAG = "KSManager"
        const val AM_KEYSTORE_FILE_NAME = "am_keystore.bks"
        const val AM_KEYSTORE = "BKS"
        const val PREF_AM_KEYSTORE_PASS = "kspass"
        const val SIGNING_KEY_ALIAS = "signing_key"

        @Volatile
        private var sInstance: KeyStoreManager? = null

        @Synchronized
        fun getInstance(context: Context): KeyStoreManager {
            return sInstance ?: KeyStoreManager(context.applicationContext).also { sInstance = it }
        }

        @Synchronized
        fun reloadKeyStore(context: Context) {
            sInstance = KeyStoreManager(context.applicationContext)
        }

        @Synchronized
        fun clearCachedKeyStore() {
            sInstance = null
        }
    }

    private val mContext = context.applicationContext
    private var mAmKeyStore: KeyStore
    private val mKeyStoreFile = File(mContext.filesDir, AM_KEYSTORE_FILE_NAME)
    private val sSharedPreferences: SharedPreferences =
        mContext.getSharedPreferences("keystore", Context.MODE_PRIVATE)

    init {
        mAmKeyStore = getAmKeyStore()
    }

    private fun getAmKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(AM_KEYSTORE)
        val password = getAmKeyStorePassword()
        try {
            if (mKeyStoreFile.exists()) {
                FileInputStream(mKeyStoreFile).use { input -> keyStore.load(input, password) }
            } else {
                keyStore.load(null, password)
            }
        } finally {
            clearChars(password)
        }
        return keyStore
    }

    @Throws(KeyStoreException::class)
    fun getAmKeyStorePassword(): CharArray {
        val encryptedPass = sSharedPreferences.getString(PREF_AM_KEYSTORE_PASS, null)
        if (encryptedPass == null) return generateAndStoreNewPassword()
        return try {
            decryptPassword(encryptedPass)
        } catch (_: Exception) {
            generateAndStoreNewPassword()
        }
    }

    fun hasSavedKeyStorePassword(): Boolean = sSharedPreferences.contains(PREF_AM_KEYSTORE_PASS)

    fun hasKeyStorePassword(): Boolean = try {
        getAmKeyStorePassword()
        true
    } catch (_: Exception) {
        false
    }

    fun hasKeyStore(): Boolean = mKeyStoreFile.exists()

    @Throws(KeyStoreException::class)
    private fun generateAndStoreNewPassword(): CharArray {
        val password = generateRandomPassword()
        val encrypted = encryptPassword(password)
        sSharedPreferences.edit().putString(PREF_AM_KEYSTORE_PASS, encrypted).apply()
        return password
    }

    private fun generateRandomPassword(): CharArray {
        val bytes = java.security.SecureRandom().generateSeed(32)
        return Base64.encodeToString(bytes, Base64.NO_WRAP).toCharArray()
    }

    private fun encryptPassword(password: CharArray): String =
        Base64.encodeToString(password.concatToString().toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

    private fun decryptPassword(encryptedPass: String): CharArray =
        String(Base64.decode(encryptedPass, Base64.NO_WRAP), Charsets.UTF_8).toCharArray()

    private fun clearChars(chars: CharArray) = java.util.Arrays.fill(chars, '\u0000')

    @Throws(KeyStoreException::class, CertificateException::class, IOException::class, NoSuchAlgorithmException::class)
    fun insertKeyPair(alias: String, keyPair: KeyPair) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore.setKeyEntry(alias, keyPair.privateKey, password, arrayOf(keyPair.certificate))
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    @Throws(KeyStoreException::class, IOException::class, NoSuchAlgorithmException::class, CertificateException::class)
    fun importKeyFromP12(p12File: File, p12Password: String, alias: String = SIGNING_KEY_ALIAS): Boolean {
        if (!p12File.exists()) throw IOException("PKCS12 file not found: ${p12File.absolutePath}")

        val p12Store = KeyStore.getInstance("PKCS12")
        FileInputStream(p12File).use { input -> p12Store.load(input, p12Password.toCharArray()) }

        val aliases = p12Store.aliases()
        var keyAlias: String? = null
        while (aliases.hasMoreElements()) {
            val candidate = aliases.nextElement()
            if (p12Store.isKeyEntry(candidate)) {
                keyAlias = candidate
                break
            }
        }

        val resolvedAlias = keyAlias ?: throw KeyStoreException("No private key found in PKCS12 file")
        val privateKey = p12Store.getKey(resolvedAlias, p12Password.toCharArray()) as? PrivateKey
            ?: throw KeyStoreException("Failed to extract private key from PKCS12")
        val certChain = p12Store.getCertificateChain(resolvedAlias)
            ?: throw KeyStoreException("No certificate chain found in PKCS12")

        insertKeyPair(alias, KeyPair(privateKey, certChain[0] as X509Certificate))
        Log.i(TAG, "Successfully imported key from PKCS12 as '$alias'")
        return true
    }

    fun containsKey(alias: String): Boolean = try {
        mAmKeyStore.containsAlias(alias)
    } catch (_: KeyStoreException) {
        false
    }

    @Throws(KeyStoreException::class)
    fun getKeyPair(alias: String): KeyPair? {
        val key = getKey(alias)
        if (key is PrivateKey) {
            val certificate = mAmKeyStore.getCertificate(alias)
                ?: throw KeyStoreException("The alias $alias does not have a certificate.")
            return KeyPair(key, certificate)
        }
        throw KeyStoreException("The alias $alias does not have a KeyPair.")
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
    private fun getKey(alias: String): Key? {
        val password = getAmKeyStorePassword()
        return try {
            mAmKeyStore.getKey(alias, password)
        } finally {
            clearChars(password)
        }
    }

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun saveKeyStore(password: CharArray) {
        FileOutputStream(mKeyStoreFile).use { output -> mAmKeyStore.store(output, password) }
    }

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    fun removeKey(alias: String) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore.deleteEntry(alias)
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    fun getAliases(): List<String> = try {
        mAmKeyStore.aliases().toList()
    } catch (_: KeyStoreException) {
        emptyList()
    }
}
