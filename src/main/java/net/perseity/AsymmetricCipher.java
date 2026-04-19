package net.perseity;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Defines the contract for an Asymmetric Cryptography implementation (like RSA or ECC).
 * Asymmetric algorithms use a pair of keys (Public and Private) to encrypt, decrypt, 
 * sign, and verify data.
 */
public interface AsymmetricCipher {
    
    /**
     * Gets the standard name of the cryptographic algorithm being used.
     * 
     * @return The standard algorithm name (e.g., "RSA", "EC", "RSASSA-PSS").
     */
    String getAlgorithm();

    /**
     * Decrypts a base64 encoded ciphertext using the Private Key.
     * 
     * @param encrypted The base64 encoded ciphertext to decrypt.
     * @return The decrypted plaintext message as a String.
     * @throws Exception If decryption fails due to invalid key, padding, or other cryptographic errors.
     */
    String decrypt(String encrypted) throws Exception;

    /**
     * Encrypts a plaintext message using the Public Key and returns base64.
     * 
     * @param message The plaintext message to encrypt.
     * @return The encrypted ciphertext as a base64 encoded String.
     * @throws Exception If encryption fails due to invalid key or other cryptographic errors.
     */
    String encrypt(String message) throws Exception;

    /**
     * Verifies a base64 digital signature of the message's SHA-256 hash using the Public Key.
     * 
     * @param message The original message that was signed.
     * @param signature The base64 encoded digital signature to verify.
     * @return true if the signature is valid and matches the message; false otherwise.
     * @throws Exception If signature verification fails due to internal cryptographic errors.
     */
    boolean isSignatureValid(String message, String signature) throws Exception;

    /**
     * Creates a base64 digital signature of the message's SHA-256 hash using the Private Key.
     * 
     * @param message The message to sign.
     * @return The digital signature as a base64 encoded String.
     * @throws Exception If signing fails due to invalid key or other cryptographic errors.
     */
    String sign(String message) throws Exception;

    /**
     * Returns the underlying Java PrivateKey object.
     * 
     * @return The private key used by this cipher.
     */
    PrivateKey getPrivateKey();

    /**
     * Returns the underlying Java PublicKey object.
     * 
     * @return The public key used by this cipher.
     */
    PublicKey getPublicKey();

    /**
     * Manually sets the internal KeyPair instance.
     * 
     * @param keyPair The KeyPair (Public and Private) to be used by this cipher.
     */
    void setKeyPair(KeyPair keyPair);

    /**
     * Generates a short, unique identifier (fingerprint) for the Public Key.
     * 
     * @return A hexadecimal string representing the Public Key's ID.
     * @throws Exception If calculation of the Key ID fails.
     */
    String getPublicKeyId() throws Exception;

    /**
     * Generates a short, unique identifier (fingerprint) for the Private Key.
     * 
     * @return A hexadecimal string representing the Private Key's ID.
     * @throws Exception If calculation of the Key ID fails.
     */
    String getPrivateKeyId() throws Exception;
}
