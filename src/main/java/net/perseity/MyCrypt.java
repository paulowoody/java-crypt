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

public class MyCrypt {
    private static final int KEY_SIZE = 256;
    private static final int IV_SIZE = 12;
    private static final int SALT_SIZE = 16;
    private static final int PBE_ITERATIONS = 65535;
    private static final String AES_GCM_NOPADDING = "AES/GCM/NoPadding";

    private SecretKey secretKey;

    public MyCrypt() throws NoSuchAlgorithmException {
        secretKey = generateSecretKey();
    }

    public MyCrypt(String b64Key) throws NoSuchAlgorithmException {
        setSecretKey(b64Key);
    }

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

    private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        return salt;
    }

    public void generateKeyFromPassword(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = generateSalt();
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, PBE_ITERATIONS, KEY_SIZE);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey key = secretKeyFactory.generateSecret(keySpec);
        secretKey = new SecretKeySpec(key.getEncoded(), "AES");
    }

    public String getSecretKey() {
        return Helper.b64Encode(secretKey.getEncoded());
    }

    public void setSecretKey(String b64Key) {
        secretKey = new SecretKeySpec(Helper.b64Decode(b64Key), "AES");
    }

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
