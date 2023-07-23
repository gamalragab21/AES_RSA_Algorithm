package com.example.aesrsaalgorithm.android.helpers.keyStore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.example.aesrsaalgorithm.android.helpers.toLog
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher

object KeyStoreRSAHelper {

    private val keyStore: KeyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER)
    }

    fun checkIfPublicKeyExistsInKeyStore(IKAlias: String): Boolean {
        return try {
            keyStore.load(null)
            keyStore.containsAlias(IKAlias)
        } catch (e: Exception) {
            false
        }
    }

    fun getPublicKeyFromRSA(IKAlias: String): PublicKey = generateKeyPair(IKAlias).public
    fun getPrivateKeyFromRSA(IKAlias: String): PrivateKey = generateKeyPair(IKAlias).private

    fun generateKeyPair(keyAlias: String): KeyPair {
        return if (checkIfPublicKeyExistsInKeyStore(keyAlias)) {
            // Key pair already exists, retrieve it from the keystore
           "Key pair already exists, retrieve it from the keystore".toLog()
            val privateKeyEntry = keyStore.getEntry(keyAlias, null) as? KeyStore.PrivateKeyEntry
            val publicKey = privateKeyEntry?.certificate?.publicKey
            val privateKey = privateKeyEntry?.privateKey
            KeyPair(publicKey, privateKey)
        } else {
            // Generate a new key pair
           "Generate a new key pair".toLog()
            val keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, KEYSTORE_PROVIDER)
            val spec = KeyGenParameterSpec.Builder(
                keyAlias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(KEY_SIZE_RSA)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setRandomizedEncryptionRequired(true)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()
            keyPairGenerator.initialize(spec)
            val newKeyPair = keyPairGenerator.genKeyPair()
            newKeyPair
        }
    }

    fun encryptWithPublicKey(data: ByteArray, publicKey: PublicKey): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_RSA)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        return cipher.doFinal(data)
    }

    fun encryptWithPublicKey(data: String, publicKey: PublicKey): String {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_RSA)
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val encryptedBytes = cipher.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(encryptedBytes)
    }

    fun decryptWithPrivateKey(
        encryptedData: ByteArray, privateKey: PrivateKey
    ): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_RSA)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return cipher.doFinal(encryptedData)
    }

    fun decryptWithPrivateKey(encryptedData: String, privateKey: PrivateKey): ByteArray {
        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION_RSA)
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val encryptedBytes = Base64.getDecoder().decode(encryptedData)
        return cipher.doFinal(encryptedBytes)
    }

    internal fun getPublicKeyFromBytes(keyBytes: ByteArray): PublicKey {
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(ALGORITHM)
        return keyFactory.generatePublic(keySpec)
    }

    internal fun getPrivateKeyFromBytes(keyBytes: ByteArray): PrivateKey {
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(ALGORITHM)
        return keyFactory.generatePrivate(keySpec)
    }

    fun arePublicKeysEqual(publicKey1: RSAPublicKey, publicKey2: RSAPublicKey): Boolean {
        val modulusMatch = publicKey1.modulus == publicKey2.modulus
        val exponentMatch = publicKey1.publicExponent == publicKey2.publicExponent
        return modulusMatch && exponentMatch
    }

    fun arePrivateKeysEqual(privateKey1: PrivateKey, privateKey2: PrivateKey): Boolean {
        // TODO: check if android system not provide encoding for private key
        val encodedKey1 = privateKey1.encoded
        val encodedKey2 = privateKey2.encoded
        return encodedKey1.contentEquals(encodedKey2)
    }

    internal fun deleteKey(keyAlias: String) {
        keyStore.load(null)
        keyStore.deleteEntry(keyAlias)
    }

    fun getEncodedPubKey(publicKey: PublicKey): String =
        android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.DEFAULT)!!


    private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA
    private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_ECB
    private const val PADDING = KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1
    private const val CIPHER_TRANSFORMATION_RSA = "$ALGORITHM/$BLOCK_MODE/$PADDING"
    private const val KEY_SIZE_RSA = 2048
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
}