package com.example.aesrsaalgorithm.android.helpers.keyStore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.SecretKeySpec

object KeyStoreAESHelper {

    fun getOrCreateSecretKey(keyStore: KeyStore, keyAlias: String): SecretKey {
        return (keyStore.getEntry(keyAlias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: generateSecretKey(keyAlias)
    }

    fun getSecretKeyFromBytes(keyBytes: ByteArray): SecretKey {
        val keySpec = SecretKeySpec(keyBytes, ALGORITHM)
        return SecretKeyFactory.getInstance(ALGORITHM)
            .generateSecret(keySpec)
    }

    fun destroySecretKey(secretKey: SecretKey) {
        secretKey.destroy()
    }

    fun deleteKey(keyStore: KeyStore, keyAlias: String) {
        keyStore.deleteEntry(keyAlias)
    }

    private fun generateSecretKey(keyAlias: String): SecretKey =
        KeyGenerator.getInstance(ALGORITHM, PROVIDER)
            .apply { init(getKeyGen(keyAlias)) }
            .generateKey()

    private fun getKeyGen(keyAlias: String) = KeyGenParameterSpec.Builder(
        keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    ).apply {
        setKeySize(256)
        setBlockModes(BLOCK_MODE)
        setEncryptionPaddings(PADDING)
//        setUserAuthenticationRequired(false)
        setRandomizedEncryptionRequired(true)
    }.build()

    const val PROVIDER = "AndroidKeyStore"
    private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
    private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
    private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
    const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"
}