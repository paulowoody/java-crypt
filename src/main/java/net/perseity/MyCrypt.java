package net.perseity;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

/**
 * Handles symmetric encryption and decryption using AES-GCM.
 * Symmetric encryption uses the same key (shared secret) for both encrypting and decrypting data.
 * It is much faster than asymmetric (RSA) encryption, making it ideal for encrypting large amounts of data (like messages).
 */
public class MyCrypt implements SymmetricCipher {
    /**
     * AES key size in bits (256 bits).
     */
    private static final int KEY_SIZE = 256;

    /**
     * GCM recommended initialization vector (IV) size in bytes (12 bytes).
     */
    private static final int IV_SIZE = 12;

    /**
     * Salt size for password-based key derivation in bytes (16 bytes).
     */
    private static final int SALT_SIZE = 16;

    /**
     * Number of iterations for PBKDF2 password-based key derivation (65535).
     */
    private static final int PBE_ITERATIONS = 65535;

    /**
     * The AES-GCM transformation string (AES/GCM/NoPadding).
     */
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";

    /**
     * The underlying SecretKey used for cryptographic operations.
     */
    private SecretKey secretKey;

    /**
     * Generates a new random AES shared secret key.
     * 
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     */
    public MyCrypt() throws NoSuchAlgorithmException {
        secretKey = generateSecretKey();
    }

    /**
     * Reconstructs an existing AES shared secret key from its Base64 representation.
     * 
     * @param b64Key The Base64 encoded secret key.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     */
    public MyCrypt(String b64Key) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(Helper.b64Decode(b64Key), "AES");
    }

    /**
     * Generates a random Initialization Vector (IV).
     * An IV ensures that encrypting the same message multiple times produces different ciphertexts,
     * protecting against pattern analysis.
     * 
     * @return A random IV as a byte array.
     */
    private byte[] generateIv() {
        SecureRandom random = new SecureRandom();
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Generates a new random AES SecretKey.
     * 
     * @return A randomly generated SecretKey.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     */
    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    /**
     * Helper to generate a random Salt for password-based key generation.
     * 
     * @return A random salt as a byte array.
     */
    public byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Derives a cryptographic key from a human-readable password and a salt using PBKDF2.
     * This makes brute-force guessing much harder by iteratively hashing the password and salt.
     * 
     * @param password The user-provided password to derive the key from.
     * @param salt The salt to use for derivation. Must be the same salt used during encryption to successfully decrypt.
     * @throws NoSuchAlgorithmException If the PBKDF2 algorithm is not available.
     * @throws InvalidKeySpecException If the password or salt specifications are invalid.
     */
    public void generateKeyFromPassword(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATIONS, KEY_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = secretKeyFactory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(key.getEncoded(), "AES");
    }

    /**
     * Derives a cryptographic key from a human-readable password using PBKDF2 with a random salt.
     * Note: To be able to re-derive this key later, you must know the salt used.
     * 
     * @param password The user-provided password.
     * @return The randomly generated salt used for this derivation.
     * @throws NoSuchAlgorithmException If the PBKDF2 algorithm is not available.
     * @throws InvalidKeySpecException If the password specifications are invalid.
     */
    public byte[] generateKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt();
        generateKeyFromPassword(password, salt);
        return salt;
    }

    /**
     * Returns the raw bytes of the secret key, encoded as a Base64 string for easy transmission.
     * 
     * @return The Base64 encoded secret key.
     */
    @Override
    public String getSecretKey() {
        return Helper.b64Encode(secretKey.getEncoded());
    }

    /**
     * Replaces the current secret key with one provided as a Base64 string.
     * 
     * @param b64Key The Base64 encoded secret key to set.
     */
    public void setSecretKey(String b64Key) {
        secretKey = new SecretKeySpec(Helper.b64Decode(b64Key), "AES");
    }

    /**
     * Encrypts plaintext using AES-GCM. 
     * GCM (Galois/Counter Mode) inherently includes an authentication tag, ensuring the data is not tampered with.
     * The randomly generated IV is prepended to the resulting ciphertext so the decrypter can use it.
     * 
     * @param plaintext The plaintext String to encrypt.
     * @return The encrypted ciphertext, prepended with the IV, as a Base64 encoded String.
     * @throws NoSuchPaddingException If the requested padding is not available.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     * @throws InvalidAlgorithmParameterException If the IV specification is invalid.
     * @throws InvalidKeyException If the secret key is invalid.
     * @throws IllegalBlockSizeException If the block size is invalid.
     * @throws BadPaddingException If the padding is incorrect.
     */
    @Override
    public String encrypt(String plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        byte[] iv = generateIv();
        int tLen = cipher.getBlockSize() * Byte.SIZE;
        GCMParameterSpec ivSpec = new GCMParameterSpec(tLen, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // prepend IV bytes to ciphertext
        byte[] encrypted = Helper.appendByteArray(iv, ciphertext);
        return Helper.b64Encode(encrypted);
    }

    /**
     * Decrypts ciphertext using AES-GCM.
     * It extracts the IV prepended to the ciphertext, then uses the shared secret to decrypt.
     * Thanks to GCM, this step will fail (throwing AEADBadTagException) if the ciphertext was tampered with in transit.
     * 
     * @param ciphertext The Base64 encoded ciphertext (prepended with IV) to decrypt.
     * @return The original decrypted plaintext String.
     * @throws NoSuchPaddingException If the requested padding is not available.
     * @throws NoSuchAlgorithmException If the AES algorithm is not available.
     * @throws InvalidAlgorithmParameterException If the IV specification is invalid.
     * @throws InvalidKeyException If the secret key is invalid.
     * @throws IllegalBlockSizeException If the block size is invalid.
     * @throws BadPaddingException If the decryption fails (e.g., due to tampering).
     */
    @Override
    public String decrypt(String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertextBytes = Helper.b64Decode(ciphertext);
        if (ciphertextBytes.length < IV_SIZE) {
            throw new IllegalArgumentException("Ciphertext is too short (must include IV).");
        }
        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        int tLen = cipher.getBlockSize() * Byte.SIZE;

        // extract IV as prefix from ciphertext
        byte[] iv = Arrays.copyOfRange(ciphertextBytes, 0, IV_SIZE);
        GCMParameterSpec ivSpec = new GCMParameterSpec(tLen, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

        // extract ciphertext following iv
        byte[] plaintextBytes = cipher.doFinal(ciphertextBytes, iv.length, ciphertextBytes.length - iv.length);
        return new String(plaintextBytes, StandardCharsets.UTF_8);
    }

    /**
     * Creates a digital signature for a message using HMAC SHA-256 of the message's SHA-256 hash.
     * 
     * @param message The message to sign.
     * @return The digital signature as a base64 encoded String.
     * @throws NoSuchAlgorithmException If the HmacSHA256 or SHA-256 algorithm is not available.
     * @throws InvalidKeyException If the secret key is invalid.
     */
    @Override
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] messageHash = Helper.hash(message);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(secretKey);
        byte[] signatureBytes = hmac.doFinal(messageHash);
        return Helper.b64Encode(signatureBytes);
    }

    /**
     * Verifies a digital signature for a message using HMAC SHA-256 and the shared secret key.
     * 
     * @param message The original message that was signed.
     * @param signature The base64 encoded digital signature to verify.
     * @return true if the signature is valid; false otherwise.
     * @throws NoSuchAlgorithmException If the HmacSHA256 or SHA-256 algorithm is not available.
     * @throws InvalidKeyException If the secret key is invalid.
     */
    @Override
    public boolean isSignatureValid(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException {
        String expectedSignature = sign(message);
        return MessageDigest.isEqual(Helper.b64Decode(expectedSignature), Helper.b64Decode(signature));
    }
}
