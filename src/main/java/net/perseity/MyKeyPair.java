package net.perseity;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.HexFormat;

/**
 * Handles asymmetric cryptography (Public/Private Key Pairs) using RSA.
 * Asymmetric cryptography uses a linked pair of keys:
 * - Public Key: Safe to share with anyone. Used to encrypt data sent to you, or to verify your signatures.
 * - Private Key: Kept strictly secret. Used to decrypt data sent to you, or to create digital signatures.
 * RSA is mathematically slow, so it's typically used to encrypt small secrets (like AES keys) rather than large messages.
 */
public class MyKeyPair {
    public static final String ALGORITHM = "RSASSA-PSS";
    private static final int SIZE = 1024; // Key size in bits. Note: 1024 is considered weak today; 2048 or 4096 is recommended for production.
    private static final String HASH = "SHA-256";
    private static final String MASK_GEN_FN = "MGF1";
    private static final String CYPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private java.security.KeyPair keyPair;

    /**
     * Generates a brand new, random RSA Public/Private Key Pair.
     */
    public MyKeyPair() throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(SIZE, random);
        keyPair = generator.generateKeyPair();
    }

    /**
     * Loads an existing RSA Key Pair from stored Base64 string files.
     */
    public MyKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyPair = Helper.readKeyPair(publicKeyFile, privateKeyFile);
    }

    /**
     * Manually sets the internal KeyPair instance.
     */
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Decrypts a message using this instance's Private Key.
     * Only the owner of the Private Key can read data that was encrypted with their Public Key.
     */
    public String decrypt(String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decodedBytes = Helper.b64Decode(encrypted);
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts a message using this instance's Public Key.
     * Anyone can use the Public Key to encrypt a message, but only the Private Key owner can decrypt it.
     */
    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(messageBytes);
        return Helper.b64Encode(encryptedBytes);
    }

    /**
     * Verifies a digital signature using this instance's Public Key.
     * This proves that the message was signed by the owner of the corresponding Private Key and hasn't been altered.
     */
    public boolean isSignatureValid(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        byte[] signatureBytes = Helper.b64Decode(signature);
        byte[] messageBytes = message.getBytes();
        Signature signatureVerifier = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signatureVerifier.setParameter(pssParameterSpec);
        signatureVerifier.initVerify(getPublicKey());
        signatureVerifier.update(messageBytes);
        return signatureVerifier.verify(signatureBytes);

    }

    /**
     * Creates a digital signature for a message using this instance's Private Key.
     * A signature proves authenticity (who sent it) and integrity (it wasn't tampered with).
     */
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signature.setParameter(pssParameterSpec);
        signature.initSign(getPrivateKey());
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        signature.update(messageBytes);
        byte[] signedBytes = signature.sign();
        return Helper.b64Encode(signedBytes);
    }

    /**
     * Returns the underlying Java PrivateKey object.
     */
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    /**
     * Returns the underlying Java PublicKey object.
     */
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }


    /**
     * Generates a short, unique identifier (fingerprint) for the Public Key.
     * Useful for comparing keys or displaying them in logs without printing the massive raw key string.
     */
    public String getPublicKeyId() throws NoSuchAlgorithmException {
        KeySpec publicKeySpec = getKeySpec(keyPair.getPublic());
        return calculateKeyId(publicKeySpec);
    }

    /**
     * Generates a short, unique identifier (fingerprint) for the Private Key.
     */
    public String getPrivateKeyId() throws NoSuchAlgorithmException {
        KeySpec privateKeySpec = getKeySpec(keyPair.getPrivate());
        return calculateKeyId(privateKeySpec);
    }

    /**
     * Extracts the mathematical properties (modulus and exponent) that make up an RSA key.
     */
    private KeySpec getKeySpec(Key key) {
        if (key instanceof RSAPublicKey publicKey) {
            return new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getPublicExponent());
        } else if (key instanceof RSAPrivateKey privateKey) {
            return new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent());
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }
    }

    /**
     * Calculates the Key ID by combining the mathematical properties of the key,
     * hashing them with SHA-256, and taking the first 8 bytes.
     */
    private String calculateKeyId(KeySpec keySpec) throws NoSuchAlgorithmException {
        BigInteger modulus;
        BigInteger exponent;
        if (keySpec instanceof RSAPublicKeySpec publicKeySpec) {
            modulus = publicKeySpec.getModulus();
            exponent = publicKeySpec.getPublicExponent();
        } else if (keySpec instanceof RSAPrivateKeySpec privateKeySpec) {
            modulus = privateKeySpec.getModulus();
            exponent = privateKeySpec.getPrivateExponent();
        } else {
            throw new IllegalArgumentException("Unsupported key specification type");
        }
        byte[] combinedBytes = appendByteArray(modulus.toByteArray(), exponent.toByteArray());
        MessageDigest sha256 = MessageDigest.getInstance(HASH);
        byte[] hash = sha256.digest(combinedBytes);
        byte[] keyId = new byte[8];
        System.arraycopy(hash, 0, keyId, 0, 8);
        return bytesToHexString(keyId).toUpperCase();
    }

    /**
     * Helper method to concatenate two byte arrays.
     */
    private byte[] appendByteArray(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Converts a byte array into a colon-separated hexadecimal string format (e.g., "1A:2B:3C").
     */
    private String bytesToHexString(byte[] bytes) {
        HexFormat hexFormat = HexFormat.ofDelimiter(":");
        return hexFormat.formatHex(bytes).toUpperCase();
    }
}
