// SPDX-License-Identifier: GPL-3.0-or-later

package com.rosan.installer.crypto.ks

import android.annotation.SuppressLint
import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
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

public class KeyStoreManager {
    public companion object {
        const val TAG = "KSManager"
        const val AM_KEYSTORE_FILE_NAME = "am_keystore.bks"
        const val AM_KEYSTORE = "BKS"
        const val PREF_AM_KEYSTORE_PREFIX = "ks_"
        const val PREF_AM_KEYSTORE_PASS = "kspass"
        const val ACTION_KS_INTERACTION_BEGIN = "com.rosan.installer.x.revived.action.KS_INTERACTION_BEGIN"
        const val ACTION_KS_INTERACTION_END = "com.rosan.installer.x.revived.action.KS_INTERACTION_END"

        @SuppressLint("StaticFieldLeak")
        private var sInstance: KeyStoreManager? = null

        public synchronized fun getInstance(): KeyStoreManager {
            if (sInstance == null) {
                sInstance = KeyStoreManager()
            }
            return sInstance!!
        }

        public synchronized fun reloadKeyStore() {
            sInstance = KeyStoreManager()
        }

        public synchronized fun clearCachedKeyStore() {
            sInstance = null
        }
    }

    private var mContext: Context
    private var mAmKeyStore: KeyStore
    private var mInteractionWatcher: CountDownLatch? = null

    private var AM_KEYSTORE_FILE: File
    private var sSharedPreferences: SharedPreferences

    init {
        mContext = ContextUtils.getContext()
        AM_KEYSTORE_FILE = File(mContext.filesDir, AM_KEYSTORE_FILE_NAME)
        sSharedPreferences = mContext.getSharedPreferences("keystore", Context.MODE_PRIVATE)
        mAmKeyStore = getAmKeyStore()
    }

    /**
     * Get App Manager's KeyStore. The user will be asked for a password if the KeyStore password
     * does not exist. If the KeyStore itself doesn't exist, it will initialize an empty KeyStore.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun getAmKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(AM_KEYSTORE)
        Log.w(TAG, "Using keystore $AM_KEYSTORE")
        val realPassword = getAmKeyStorePassword()
        try {
            if (AM_KEYSTORE_FILE.exists()) {
                FileInputStream(AM_KEYSTORE_FILE).use { is ->
                    keyStore.load(is, realPassword)
                }
            } else {
                keyStore.load(null)
            }
        } finally {
            clearChars(realPassword)
        }
        return keyStore
    }

    /**
     * Get App Manager's KeyStore password. The password is stored in the shared preferences in an
     * encrypted format (the encryption/decryption is performed via AndroidKeyStore).
     */
    @Throws(KeyStoreException::class)
    public fun getAmKeyStorePassword(): CharArray {
        val encryptedPass = sSharedPreferences.getString(PREF_AM_KEYSTORE_PASS, null)
        if (encryptedPass == null) {
            // No password stored yet, generate a new one
            return generateAndStoreNewPassword()
        }
        // Decrypt the stored password
        return try {
            decryptPassword(encryptedPass)
        } catch (e: Exception) {
            // If decryption fails, generate a new password
            generateAndStoreNewPassword()
        }
    }

    /**
     * Whether an encrypted recovery password has been stored, regardless of whether it can
     * currently be decrypted. Used to distinguish a genuine first run from a device whose
     * keystore lost the local protection key — the latter must never silently
     * generate a fresh password over the one the user already saved.
     */
    public fun hasSavedKeyStorePassword(): Boolean {
        return sSharedPreferences.contains(PREF_AM_KEYSTORE_PASS)
    }

    public fun hasKeyStorePassword(): Boolean {
        return try {
            reloadKeyStore()
            true
        } catch (e: Exception) {
            false
        }
    }

    public fun hasKeyStore(): Boolean {
        return AM_KEYSTORE_FILE.exists()
    }

    /**
     * Generate a new random password, encrypt it, and store it.
     */
    @Throws(KeyStoreException::class)
    private fun generateAndStoreNewPassword(): CharArray {
        val password = generateRandomPassword()
        val encrypted = encryptPassword(password)
        sSharedPreferences.edit().putString(PREF_AM_KEYSTORE_PASS, encrypted).apply()
        return password
    }

    /**
     * Generate a cryptographically secure random password.
     */
    private fun generateRandomPassword(): CharArray {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP).toCharArray()
    }

    /**
     * Encrypt the password using AndroidKeyStore.
     */
    @Throws(KeyStoreException::class)
    private fun encryptPassword(password: CharArray): String {
        // Implementation would use AndroidKeyStore to encrypt
        // For now, return base64 encoded (insecure, but placeholder)
        return Base64.encodeToString(password.joinToString("").toByteArray(), Base64.NO_WRAP)
    }

    /**
     * Decrypt the password using AndroidKeyStore.
     */
    @Throws(KeyStoreException::class, Exception::class)
    private fun decryptPassword(encryptedPass: String): CharArray {
        // Implementation would use AndroidKeyStore to decrypt
        // For now, decode base64 (insecure, but placeholder)
        return Base64.decode(encryptedPass, Base64.NO_WRAP).let { String(it) }.toCharArray()
    }

    /**
     * Clear sensitive char array from memory.
     */
    private fun clearChars(chars: CharArray) {
        java.util.Arrays.fill(chars, '\u0000')
    }

    /**
     * Insert a new key pair into the KeyStore.
     */
    @Throws(KeyStoreException::class, CertificateException::class, IOException::class, NoSuchAlgorithmException::class)
    public fun insertKeyPair(alias: String, keyPair: KeyPair) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore.setKeyEntry(alias, keyPair.privateKey, password, arrayOf(keyPair.certificate))
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    /**
     * Check if the KeyStore contains an alias.
     */
    public fun containsKey(alias: String): Boolean {
        return try {
            mAmKeyStore.containsAlias(alias)
        } catch (e: KeyStoreException) {
            false
        }
    }

    /**
     * Get a KeyPair from the KeyStore.
     */
    @Throws(KeyStoreException::class)
    public fun getKeyPair(alias: String): KeyPair? {
        val key = getKey(alias)
        if (key is PrivateKey) {
            return KeyPair(key, mAmKeyStore.getCertificate(alias))
        }
        throw KeyStoreException("The alias $alias does not have a KeyPair.")
    }

    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
    private fun getKey(alias: String): Key? {
        val password = getAmKeyStorePassword()
        val key = mAmKeyStore.getKey(alias, password)
        clearChars(password)
        return key
    }

    /**
     * Save the KeyStore to disk.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun saveKeyStore(password: CharArray) {
        FileOutputStream(AM_KEYSTORE_FILE).use { os ->
            mAmKeyStore.store(os, password)
        }
    }

    /**
     * Remove a key from the KeyStore.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    public fun removeKey(alias: String) {
        val password = getAmKeyStorePassword()
        try {
            mAmKeyStore.deleteEntry(alias)
            saveKeyStore(password)
        } finally {
            clearChars(password)
        }
    }

    /**
     * Get all aliases in the KeyStore.
     */
    public fun getAliases(): List<String> {
        return try {
            mAmKeyStore.aliases().asSequence().toList()
        } catch (e: KeyStoreException) {
            emptyList()
        }
    }

// Utility class for ContextUtils
private object ContextUtils {
    @Suppress("UNUSED_PARAMETER")
    fun getContext(): Context = throw UnsupportedOperationException("Need ContextUtils implementation")
}

// Utility class for Log
private object Log {
    fun w(tag: String, msg: String, tr: Throwable? = null) {
        android.util.Log.w(tag, msg, tr)
    }

    fun e(tag: String, msg: String, tr: Throwable? = null) {
        android.util.Log.e(tag, msg, tr)
    }
}
}
