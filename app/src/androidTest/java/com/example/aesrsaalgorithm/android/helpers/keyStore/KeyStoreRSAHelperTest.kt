package com.example.aesrsaalgorithm.android.helpers.keyStore

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.PrivateKey
import java.security.interfaces.RSAPublicKey


@RunWith(AndroidJUnit4::class)
internal class KeyStoreRSAHelperTest {

    private lateinit var keyStoreRSAHelper: KeyStoreRSAHelper
    private val testKeyAlias = "02f1f214-6c71-3f85-acd0-d969a69f56d2"

    @Before
    fun setup() {
        keyStoreRSAHelper = KeyStoreRSAHelper
    }

    @After
    fun after() {
        keyStoreRSAHelper.deleteKey(testKeyAlias)
    }

    @Test
    fun testCheckIfPublicKeyExistsInKeyStore_keyExists_returnsTrue() {
        // Add the public key to the keystore
        keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val result = keyStoreRSAHelper.checkIfPublicKeyExistsInKeyStore(testKeyAlias)
        assertTrue(result)
    }

    @Test
    fun testCheckIfPublicKeyExistsInKeyStore_keyDoesNotExist_returnsFalse() {
        // No key is added to the keystore
        val result = keyStoreRSAHelper.checkIfPublicKeyExistsInKeyStore(testKeyAlias)
        println(result)
        assertFalse(result)
    }

    @Test
    fun testGetPublicKeyFromRSA_keyExists_returnsPublicKey() {
        // Add the public key to the keystore
        keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val publicKey = keyStoreRSAHelper.getPublicKeyFromRSA(testKeyAlias)
        assertNotNull(publicKey)
    }

    @Test
    fun testGetPublicKeyFromRSA_keyDoesNotExist_generatesKeyPairAndReturnsPublicKey() {
        // No key is added to the keystore
        val publicKey = keyStoreRSAHelper.getPublicKeyFromRSA(testKeyAlias)
        assertNotNull(publicKey)
    }

    @Test
    fun testGenerateKeyPair_keyAliasDoesNotExist_generatesNewKeyPair() {
        // No key is added to the keystore
        val generatedKeyPair = keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        assertNotNull(generatedKeyPair)
    }

    @Test
    fun testEncryptWithPublicKeyAndDecryptWithPrivateKey_validDataAndKeyPair_returnsOriginalData() {
        val data = "DF557E93A1B4A11C1927B71BCDFB6900".toByteArray()
        val keyPair = keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val encryptedData = keyStoreRSAHelper.encryptWithPublicKey(data, keyPair.public)
        val decryptedData = keyStoreRSAHelper.decryptWithPrivateKey(encryptedData, keyPair.private)
        assertArrayEquals(data, decryptedData)
    }

    @Test
    fun testEncryptWithPublicKeyWhenKeyStoreExistAndDecryptWithPrivateKey_validDataAndKeyPair_returnsOriginalData() {
        val data = "Test data".toByteArray()
        val keyPairEnc = keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val keyPairDec = keyStoreRSAHelper.generateKeyPair(testKeyAlias)

        val encryptedData1 = keyStoreRSAHelper.encryptWithPublicKey(data, keyPairEnc.public)
        val decryptedData1 =
            keyStoreRSAHelper.decryptWithPrivateKey(encryptedData1, keyPairDec.private)

        val encryptedData2 = keyStoreRSAHelper.encryptWithPublicKey(data, keyPairDec.public)
        val decryptedData2 =
            keyStoreRSAHelper.decryptWithPrivateKey(encryptedData2, keyPairEnc.private)

        assertArrayEquals(data, decryptedData1)
        assertArrayEquals(data, decryptedData2)
    }

    @Test
    fun testDeleteKey_keyExistsInKeyStore_deletesKey() {
        // Add the public key to the keystore
        keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        keyStoreRSAHelper.deleteKey(testKeyAlias)
        assertFalse(keyStoreRSAHelper.checkIfPublicKeyExistsInKeyStore(testKeyAlias))
    }

    @Test
    fun testDeleteKey_keyDoesNotExistInKeyStore_doesNothing() {
        // No key is added to the keystore
        keyStoreRSAHelper.deleteKey(testKeyAlias)
        // Assert
        // No exception should be thrown
    }

    @Test
    fun testGetPublicKeyFromBytes_validKeyBytes_returnsPublicKey() {
        val keyPair = keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val publicKeyBytes = keyPair.public.encoded
        val publicKey = keyStoreRSAHelper.getPublicKeyFromBytes(publicKeyBytes)
        assertNotNull(publicKey)
    }

    @Test
    fun testGenerateKeyPair_keyAliasAlreadyExists_returnsExistingKeyPair() {
        // Add the key pair to the keystore
        val keyPair = keyStoreRSAHelper.generateKeyPair(testKeyAlias)
        val generatedKeyPair = keyStoreRSAHelper.generateKeyPair(testKeyAlias)

        assertTrue(
            keyStoreRSAHelper.arePublicKeysEqual(
                keyPair.public as RSAPublicKey,
                generatedKeyPair.public as RSAPublicKey
            )
        )

        assertTrue(
            keyStoreRSAHelper.arePrivateKeysEqual(
                keyPair.private as PrivateKey,
                generatedKeyPair.private as PrivateKey
            )
        )
    }
}