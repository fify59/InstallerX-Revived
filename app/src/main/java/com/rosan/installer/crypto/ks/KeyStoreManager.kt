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
    }

    private var mContext: Context
    private var mAmKeyStore: KeyStore
    private var mInteractionWatcher: CountDownLatch? = null

    @SuppressLint("StaticFieldLeak")
    private var sInstance: KeyStoreManager? = null

    private var AM_KEYSTORE_FILE: File
    private var sSharedPreferences: SharedPreferences

    init {
        mContext = ContextUtils.getContext()
        AM_KEYSTORE_FILE = File(mContext.filesDir, AM_KEYSTORE_FILE_NAME)
        sSharedPreferences = mContext.getSharedPreferences("keystore", Context.MODE_PRIVATE)
        mAmKeyStore = getAmKeyStore()
    }

    public static synchronized fun getInstance(): KeyStoreManager {
        if (sInstance == null) {
            sInstance = KeyStoreManager()
        }
        return sInstance!!
    }

    public static synchronized fun reloadKeyStore() {
        sInstance = KeyStoreManager()
    }

    public static synchronized fun clearCachedKeyStore() {
        sInstance = null
    }

    /**
     * Whether an encrypted recovery password has been stored, regardless of whether it can
     * currently be decrypted. Used to distinguish a genuine first run from a device whose
     * keystore lost the local protection key — the latter must never silently
     * generate a fresh password over the one the user already saved.
     */
    public static fun hasSavedKeyStorePassword(): Boolean {
        return sSharedPreferences.contains(PREF_AM_KEYSTORE_PASS)
    }

    public static fun hasKeyStorePassword(): Boolean {
        return try {
            reloadKeyStore()
            true
        } catch (e: Exception) {
            false
        }
    }

    public static fun hasKeyStore(): Boolean {
        return AM_KEYSTORE_FILE.exists()
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
            ?: throw KeyStoreException("No saved password for KeyStore.")
        val realPassword = getDecryptedPassword(mContext, encryptedPass)
            ?: throw KeyStoreException("Could not decrypt encrypted password.")
        return realPassword
    }

    /**
     * Get the password decrypted by Android KeyStore.
     */
    @SuppressLint("AndroidKeystore")
    private fun getDecryptedPassword(context: Context, encryptedPass: String): CharArray? {
        var encryptedBytes: ByteArray? = null
        var decryptedBytes: ByteArray? = null
        try {
            encryptedBytes = Base64.decode(encryptedPass, Base64.NO_WRAP)
            decryptedBytes = CompatUtil.decryptData(context, encryptedBytes)
            return bytesToChars(decryptedBytes)
        } catch (e: Exception) {
            // Do not log encryptedPass: ciphertext of the keystore password does not belong in logcat
            Log.e("KS", "Could not get decrypted password", e)
        } finally {
            clearBytes(encryptedBytes)
            clearBytes(decryptedBytes)
        }
        return null
    }

    /**
     * Get the password to be encrypted using Android KeyStore.
     */
    private fun getEncryptedPassword(context: Context, realPass: CharArray): String? {
        var realPassBytes: ByteArray? = null
        var encodedBytes: ByteArray? = null
        try {
            val bos = ByteArrayOutputStream()
            realPassBytes = charsToBytes(realPass)
            val encryptedData = CompatUtil.getEncryptedData(realPassBytes, context)
            bos.write(encryptedData.iv.size.toByte())
            bos.write(encryptedData.iv)
            bos.write(encryptedData.encryptedData)
            encodedBytes = bos.toByteArray()
            return Base64.encodeToString(encodedBytes, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("KS", "Could not get encrypted password", e)
        } finally {
            clearBytes(realPassBytes)
            clearBytes(encodedBytes)
        }
        return null
    }

    /**
     * Save password in the Shared Preferences in encrypted form.
     */
    private fun savePass(context: Context, prefAlias: String, password: CharArray): Boolean {
        val encryptedPass = getEncryptedPassword(context, password)
        if (encryptedPass == null) {
            return false
        }
        sSharedPreferences.edit().putString(prefAlias, encryptedPass).apply()
        return true
    }

    private fun getPrefAlias(alias: String): String {
        return PREF_AM_KEYSTORE_PREFIX + alias
    }

    /**
     * Check if a key exists in the KeyStore.
     */
    @Throws(KeyStoreException::class)
    public fun containsKey(alias: String): Boolean {
        return mAmKeyStore.containsAlias(alias)
    }

    /**
     * Add a key pair to the KeyStore.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    public fun addKeyPair(alias: String, keyPair: KeyPair, isOverride: Boolean): Boolean {
        val prefAlias = getPrefAlias(alias)
        if (sSharedPreferences.contains(prefAlias) && mAmKeyStore.containsAlias(alias)) {
            Log.w(TAG, "Alias $alias exists.")
            if (!isOverride) return false
            removeItemInternal(alias)
        }
        val password = getAmKeyStorePassword()
        mAmKeyStore.setKeyEntry(alias, keyPair.privateKey, password, arrayOf(keyPair.certificate))
        val encryptedPass = getEncryptedPassword(mContext, password)
        if (encryptedPass == null) {
            mAmKeyStore.deleteEntry(alias)
            throw KeyStoreException("Password for $alias could not be saved.")
        }
        sSharedPreferences.edit().putString(prefAlias, encryptedPass).apply()
        storeKeyStore(password)
        keyPair.destroy()
        return true
    }

    /**
     * Add a secret key to the KeyStore.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    public fun addSecretKey(alias: String, secretKey: SecretKey, isOverride: Boolean): Boolean {
        val prefAlias = getPrefAlias(alias)
        if (sSharedPreferences.contains(prefAlias) && mAmKeyStore.containsAlias(alias)) {
            if (!isOverride) throw KeyStoreException("Alias $alias exists.")
            else Log.w(TAG, "Alias $alias exists.")
        }
        val password = getAmKeyStorePassword()
        mAmKeyStore.setEntry(alias, KeyStore.SecretKeyEntry(secretKey), KeyStore.PasswordProtection(password))
        val encryptedPass = getEncryptedPassword(mContext, password)
        if (encryptedPass == null) {
            mAmKeyStore.deleteEntry(alias)
            throw KeyStoreException("Password for $alias could not be saved.")
        }
        sSharedPreferences.edit().putString(prefAlias, encryptedPass).apply()
        storeKeyStore(password)
        return true
    }

    /**
     * Remove an item from the KeyStore.
     */
    @Throws(KeyStoreException::class, IOException::class, CertificateException::class, NoSuchAlgorithmException::class)
    public fun removeItem(alias: String): Boolean {
        removeItemInternal(alias)
        val realPassword = getAmKeyStorePassword()
        try {
            storeKeyStore(realPassword)
        } finally {
            clearChars(realPassword)
        }
        return true
    }

    private fun removeItemInternal(alias: String) {
        mAmKeyStore.deleteEntry(alias)
        val prefAlias = getPrefAlias(alias)
        if (sSharedPreferences.contains(prefAlias)) {
            sSharedPreferences.edit().remove(prefAlias).apply()
        }
    }

    /**
     * Get a KeyPair from the KeyStore.
     */
    @Throws(UnrecoverableKeyException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
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
     * Store the KeyStore to disk.
     */
    @Throws(IOException::class, CertificateException::class, NoSuchAlgorithmException::class, KeyStoreException::class)
    private fun storeKeyStore(password: CharArray) {
        try {
            FileOutputStream(AM_KEYSTORE_FILE).use { fos ->
                mAmKeyStore.store(fos, password)
            }
        } finally {
            clearChars(password)
        }
    }

    private fun clearChars(array: CharArray?) {
        array?.let { java.util.Arrays.fill(it, '\u0000') }
    }

    private fun clearBytes(array: ByteArray?) {
        array?.let { java.util.Arrays.fill(it, 0.toByte()) }
    }

    private fun charsToBytes(chars: CharArray): ByteArray {
        return chars.joinToString("").toByteArray()
    }

    private fun bytesToChars(bytes: ByteArray): CharArray {
        return String(bytes).toCharArray()
    }
}

// Utility class for compatibility
private object CompatUtil {
    @SuppressLint("AndroidKeystore")
    fun getEncryptedData(data: ByteArray, context: Context): AesEncryptedData {
        // Use Android Keystore for encryption
        // Implementation depends on Android version
        // For now, return a placeholder
        throw UnsupportedOperationException("Need to implement encryption")
    }

    @SuppressLint("AndroidKeystore")
    fun decryptData(context: Context, encryptedData: ByteArray): ByteArray? {
        // Use Android Keystore for decryption
        // For now, return null
        return null
    }
}

private data class AesEncryptedData(
    val iv: ByteArray,
    val encryptedData: ByteArray
)

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
