package net.perseity;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12; // GCM recommended IV size is 12 bytes
    private static final int SALT_SIZE = 16;
    private static final int PBE_ITERATIONS = 65535;
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding"; // GCM mode provides both confidentiality and data authenticity

    private SecretKey secretKey;

    /**
     * Generates a new random AES shared secret key.
     */
    public MyCrypt() throws NoSuchAlgorithmException {
        secretKey = generateSecretKey();
    }

    /**
     * Reconstructs an existing AES shared secret key from its Base64 representation.
     */
    public MyCrypt(String b64Key) throws NoSuchAlgorithmException {
        this.secretKey = new SecretKeySpec(Helper.b64Decode(b64Key), "AES");
    }

    /**
     * Generates a random Initialization Vector (IV).
     * An IV ensures that encrypting the same message multiple times produces different ciphertexts,
     * protecting against pattern analysis.
     */
    private byte[] generateIv() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] iv = new byte[IV_SIZE];
        random.nextBytes(iv);
        return iv;
    }

    private SecretKey generateSecretKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    /**
     * Helper to generate a random Salt for password-based key generation.
     */
    private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Derives a cryptographic key from a human-readable password using PBKDF2.
     * This makes brute-force guessing much harder by iteratively hashing the password and salt.
     */
    public void generateKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt();
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATIONS, KEY_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = secretKeyFactory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(key.getEncoded(), "AES");
    }

    /**
     * Returns the raw bytes of the secret key, encoded as a Base64 string for easy transmission.
     */
    public String getSecretKey() {
        return Helper.b64Encode(secretKey.getEncoded());
    }

    /**
     * Replaces the current secret key with one provided as a Base64 string.
     */
    public void setSecretKey(String b64Key) {
        secretKey = new SecretKeySpec(Helper.b64Decode(b64Key), "AES");
    }

    /**
     * Encrypts plaintext using AES-GCM. 
     * GCM (Galois/Counter Mode) inherently includes an authentication tag, ensuring the data is not tampered with.
     * The randomly generated IV is prepended to the resulting ciphertext so the decrypter can use it.
     */
    public String encrypt(String plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(AES_GCM_NOPADDING);
        byte[] iv = generateIv();
        int tLen = cipher.getBlockSize() * Byte.SIZE;
        GCMParameterSpec ivSpec = new GCMParameterSpec(tLen, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // prepend IV bytes to ciphertext
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);
        return Helper.b64Encode(encrypted);
    }

    /**
     * Decrypts ciphertext using AES-GCM.
     * It extracts the IV prepended to the ciphertext, then uses the shared secret to decrypt.
     * Thanks to GCM, this step will fail (throwing AEADBadTagException) if the ciphertext was tampered with in transit.
     */
    public String decrypt(String ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] ciphertextBytes = Helper.b64Decode(ciphertext);
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
}
