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
        const val PREF_AM_KEYSTORE_PASS = "kspass"
        const val ACTION_KS_INTERACTION_BEGIN = "com.rosan.installer.x.revived.action.KS_INTERACTION_BEGIN"
        const val ACTION_KS_INTERACTION_END = "com.rosan.installer.x.revived.action.KS_INTERACTION_END"

        private var sInstance: KeyStoreManager? = null

        @Synchronized fun getInstance(): KeyStoreManager {
            if (sInstance == null) {
                sInstance = KeyStoreManager()
            }
            return sInstance!!
        }

        @Synchronized fun reloadKeyStore() {
            sInstance = KeyStoreManager()
        }

        @Synchronized fun clearCachedKeyStore() {
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

    private fun getAmKeyStore(): KeyStore {
        val keyStore = KeyStore.getInstance(AM_KEYSTORE)
        Log.w(TAG, "Using keystore $AM_KEYSTORE")
        val realPassword = getAmKeyStorePassword()
        try {
            if (AM_KEYSTORE_FILE.exists()) {
                val is = FileInputStream(AM_KEYSTORE_FILE)
                try {
                    keyStore.load(is, realPassword)
                } finally {
                    is.close()
                }
            } else {
                keyStore.load(null)
            }
        } finally {
            clearChars(realPassword)
        }
        return keyStore
    }

    @Throws(KeyStoreException::class)
    public fun getAmKeyStorePassword(): CharArray {
        val encryptedPass = sSharedPreferences.getString(PREF_AM_KEYSTORE_PASS, null)
        if (encryptedPass == null) {
            return generateAndStoreNewPassword()
        }
        return try {
            decryptPassword(encryptedPass)
        } catch (e: Exception) {
            return generateAndStoreNewPassword()
        }
    }

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

    @Throws(KeyStoreException::class)
    private fun generateAndStoreNewPassword(): CharArray {
        val password = generateRandomPassword()
        val encrypted = encryptPassword(password)
        sSharedPreferences.edit().putString(PREF_AM_KEYSTORE_PASS, encrypted).apply()
        return password
    }

    private fun generateRandomPassword(): CharArray {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP).toCharArray()
    }

    @Throws(KeyStoreException::class)
    private fun encryptPassword(password: CharArray): String {
        return Base64.encodeToString(password.joinToString("").toByteArray(), Base64.NO_WRAP)
    }

    @Throws(KeyStoreException::class, Exception::class)
    private fun decryptPassword(encryptedPass: String): CharArray {
        return Base64.decode(encryptedPass, Base64.NO_WRAP).let { String(it) }.toCharArray()
    }

    private fun clearChars(chars: CharArray) {
        java.util.Arrays.fill(chars, '\u0000')
    }

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

    public fun containsKey(alias: String): Boolean {
        return try {
            mAmKeyStore.containsAlias(alias)
        } catch (e: KeyStoreException) {
            false
        }
    }

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

    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    private fun saveKeyStore(password: CharArray) {
        val os = FileOutputStream(AM_KEYSTORE_FILE)
        try {
            mAmKeyStore.store(os, password)
        } finally {
            os.close()
        }
    }

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

    public fun getAliases(): List<String> {
        return try {
            mAmKeyStore.aliases().asSequence().toList()
        } catch (e: KeyStoreException) {
            emptyList()
        }
    }

    private object ContextUtils {
        @Suppress("UNUSED_PARAMETER")
        fun getContext(): Context = throw UnsupportedOperationException("Need ContextUtils implementation")
    }
}
