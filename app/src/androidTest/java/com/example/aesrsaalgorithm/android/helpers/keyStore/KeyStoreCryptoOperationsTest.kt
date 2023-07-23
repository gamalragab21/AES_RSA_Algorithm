package com.example.aesrsaalgorithm.android.helpers.keyStore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom


@RunWith(AndroidJUnit4::class)
internal class KeyStoreCryptoOperationsTest {

    @Test
    fun testEncryptAndDecryptData() {
        val keyAlias = "TestKeyAlias"
        val originalData = generateRandomByteArray(1024)

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, originalData)
        val decryptedData = KeyStoreCryptoOperations.decrypt(keyAlias, encryptedData)

        assertArrayEquals(originalData, decryptedData)
    }

    @Test
    fun testEncryptAndDecryptWithDifferentKeyAlias() {
        val keyAlias1 = "KeyAlias1"
        val keyAlias2 = "KeyAlias2"
        val originalData = generateRandomByteArray(512)

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias1, originalData)

        assertThrows(Exception::class.java) {
            KeyStoreCryptoOperations.decrypt(keyAlias2, encryptedData)
        }
    }

    @Test
    fun testEncryptAndDecryptEmptyData() {
        val keyAlias = "EmptyDataKeyAlias"
        val originalData = ByteArray(0)

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, originalData)
        val decryptedData = KeyStoreCryptoOperations.decrypt(keyAlias, encryptedData)

        assertArrayEquals(originalData, decryptedData)
    }


    @Test
    fun testEncryptAndDecryptLargeData() {
        val keyAlias = "LargeDataKeyAlias"
        val originalData = generateRandomByteArray(1024 * 1024) // 1MB data

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, originalData)
        val decryptedData = KeyStoreCryptoOperations.decrypt(keyAlias, encryptedData)

        assertArrayEquals(originalData, decryptedData)
    }

    @Test
    fun testDecryptWithInvalidKeyAlias() {
        val keyAlias = "ValidKeyAlias"
        val invalidKeyAlias = "InvalidKeyAlias"
        val originalData = generateRandomByteArray(256)

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, originalData)

        assertThrows(Exception::class.java) {
            KeyStoreCryptoOperations.decrypt(invalidKeyAlias, encryptedData)
        }
    }

    @Test
    fun testEncryptAndDecrypt_ValidData() {
        val keyAlias = "testKeyAlias"
        val testData = "Hello, this is a test message.".toByteArray()

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, testData)
        val decryptedData = KeyStoreCryptoOperations.decrypt(keyAlias, encryptedData)

        assertArrayEquals(testData, decryptedData)
    }

    @Test
    fun testDecrypt_ValidData() {
        val keyAlias = "testKeyAlias"
        val testData = "Hello, this is another test.".toByteArray()

        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, testData)
        val decryptedData = KeyStoreCryptoOperations.decrypt(keyAlias, encryptedData)

        assertArrayEquals(testData, decryptedData)
    }

    @Test
    fun testDecrypt_IncorrectKeyAlias() {
        val keyAlias = "testKeyAlias"
        val testData = "Hello, this is a test message.".toByteArray()
        val encryptedData = KeyStoreCryptoOperations.encrypt(keyAlias, testData)

        val incorrectKeyAlias = "incorrectKeyAlias"
        assertThrows(Exception::class.java) {
            KeyStoreCryptoOperations.decrypt(incorrectKeyAlias, encryptedData)
        }
    }

    private fun generateRandomByteArray(size: Int): ByteArray {
        val byteArray = ByteArray(size)
        SecureRandom().nextBytes(byteArray)
        return byteArray
    }
}