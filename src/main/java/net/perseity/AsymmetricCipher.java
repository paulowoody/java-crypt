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
     * @return The standard algorithm name (e.g., "RSA", "EC", "RSASSA-PSS").
     */
    String getAlgorithm();

    /**
     * Decrypts a base64 encoded ciphertext using the Private Key.
     */
    String decrypt(String encrypted) throws Exception;

    /**
     * Encrypts a plaintext message using the Public Key and returns base64.
     */
    String encrypt(String message) throws Exception;

    /**
     * Verifies a base64 digital signature using the Public Key.
     */
    boolean isSignatureValid(String message, String signature) throws Exception;

    /**
     * Creates a base64 digital signature of the message using the Private Key.
     */
    String sign(String message) throws Exception;

    /**
     * Returns the underlying Java PrivateKey object.
     */
    PrivateKey getPrivateKey();

    /**
     * Returns the underlying Java PublicKey object.
     */
    PublicKey getPublicKey();

    /**
     * Manually sets the internal KeyPair instance.
     */
    void setKeyPair(KeyPair keyPair);

    /**
     * Generates a short, unique identifier (fingerprint) for the Public Key.
     */
    String getPublicKeyId() throws Exception;

    /**
     * Generates a short, unique identifier (fingerprint) for the Private Key.
     */
    String getPrivateKeyId() throws Exception;
}
