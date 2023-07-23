package com.example.aesrsaalgorithm.android.helpers.keyStore

import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

object KeyStoreCryptoOperations {

    private val keyStore: KeyStore = KeyStore.getInstance(KeyStoreAESHelper.PROVIDER).apply {
        load(null)
    }

    fun encrypt(keyAlias: String, data: ByteArray): ByteArray {
        try {
            val secretKey = KeyStoreAESHelper.getOrCreateSecretKey(keyStore, keyAlias)
            val cipher = Cipher.getInstance(KeyStoreAESHelper.TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val encryptedData = cipher.doFinal(data)
            return cipher.iv + encryptedData
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
            throw java.lang.Exception(e.message)
        }
    }

    fun decrypt(keyAlias: String, encryptedData: ByteArray): ByteArray {
        try {
            val secretKey = KeyStoreAESHelper.getOrCreateSecretKey(keyStore, keyAlias)
            val cipher = Cipher.getInstance(KeyStoreAESHelper.TRANSFORMATION)
            val iv = encryptedData.copyOfRange(0, cipher.blockSize)
            val encryptedBytes = encryptedData.copyOfRange(cipher.blockSize, encryptedData.size)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            return cipher.doFinal(encryptedBytes)
        } catch (e: Exception) {
            e.printStackTrace()
            throw java.lang.Exception(e.message)
        }
    }

//    private fun generateIV(): IvParameterSpec {
//        val iv = ByteArray(IV_LENGTH)
//        val random = SecureRandom()
//        random.nextBytes(iv)
//        return IvParameterSpec(iv)
//    }
//
//    fun decrypt(keyAlias: String, encryptedDataWithIV: ByteArray): ByteArray {
//        try {
//            val iv = ByteArray(IV_LENGTH)
//            val encryptedData = ByteArray(encryptedDataWithIV.size - IV_LENGTH)
//            System.arraycopy(encryptedDataWithIV, 0, iv, 0, IV_LENGTH)
//            System.arraycopy(encryptedDataWithIV, IV_LENGTH, encryptedData, 0, encryptedData.size)
//
//            val secretKey = KeyStoreAESHelper.getOrCreateSecretKey(keyStore, keyAlias)
//            val cipher = Cipher.getInstance(KeyStoreAESHelper.TRANSFORMATION).apply {
//                init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
//            }
//            return cipher.doFinal(encryptedData)
//        } catch (e: Exception) {
//            getClassLogger().error(e.message)
//            e.printStackTrace()
//            throw Exception(e.message)
//        }
//    }
//
//    private const val IV_LENGTH: Int = 16  // 128 bits
}