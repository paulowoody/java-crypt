package net.perseity;

/**
 * Defines the contract for a Symmetric Cryptography implementation (like AES).
 * Symmetric algorithms use the exact same key to both encrypt and decrypt data.
 */
public interface SymmetricCipher {

    /**
     * Gets the underlying secret key being used for symmetric operations.
     * 
     * @return The underlying secret key encoded as a base64 string.
     * @throws Exception If retrieving the secret key fails.
     */
    String getSecretKey() throws Exception;

    /**
     * Encrypts a plaintext string and returns a base64 encoded ciphertext.
     * 
     * @param plaintext The plaintext string to encrypt.
     * @return The base64 encoded ciphertext.
     * @throws Exception If encryption fails due to invalid key, algorithm errors, etc.
     */
    String encrypt(String plaintext) throws Exception;

    /**
     * Decrypts a base64 encoded ciphertext and returns the original plaintext.
     * 
     * @param ciphertext The base64 encoded ciphertext to decrypt.
     * @return The original decrypted plaintext String.
     * @throws Exception If decryption fails due to invalid key, padding errors, etc.
     */
    String decrypt(String ciphertext) throws Exception;
}
