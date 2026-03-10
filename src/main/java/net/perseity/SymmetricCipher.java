package net.perseity;

/**
 * Defines the contract for a Symmetric Cryptography implementation (like AES).
 * Symmetric algorithms use the exact same key to both encrypt and decrypt data.
 */
public interface SymmetricCipher {

    /**
     * @return The underlying secret key encoded as a base64 string.
     */
    String getSecretKey() throws Exception;

    /**
     * Encrypts a plaintext string and returns a base64 encoded ciphertext.
     */
    String encrypt(String plaintext) throws Exception;

    /**
     * Decrypts a base64 encoded ciphertext and returns the original plaintext.
     */
    String decrypt(String ciphertext) throws Exception;
}
