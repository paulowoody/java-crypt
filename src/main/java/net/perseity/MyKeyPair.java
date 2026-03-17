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
public class MyKeyPair implements AsymmetricCipher {
    /**
     * The standard RSA signature algorithm (RSASSA-PSS).
     */
    public static final String ALGORITHM = "RSASSA-PSS";

    /**
     * Key size in bits (2048). 2048 or 4096 is recommended for production.
     */
    private static final int SIZE = 2048;

    /**
     * Hash algorithm used for PSS signatures and OAEP padding (SHA-256).
     */
    private static final String HASH = "SHA-256";

    /**
     * Mask generation function for RSA (MGF1).
     */
    private static final String MASK_GEN_FN = "MGF1";

    /**
     * The RSA cipher transformation string with OAEP padding (RSA/ECB/OAEPWithSHA-256AndMGF1Padding).
     */
    private static final String CYPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * The underlying Java KeyPair instance containing the public and private keys.
     */
    private java.security.KeyPair keyPair;

    /**
     * Gets the standard algorithm name used by this key pair.
     * 
     * @return The standard algorithm name.
     */
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    /**
     * Generates a brand new, random RSA Public/Private Key Pair.
     * 
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     */
    public MyKeyPair() throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = new SecureRandom();
        generator.initialize(SIZE, random);
        keyPair = generator.generateKeyPair();
    }

    /**
     * Loads an existing RSA Key Pair from stored Base64 string files.
     * 
     * @param publicKeyFile Path to the public key PEM file.
     * @param privateKeyFile Path to the private key PEM file.
     * @throws IOException If reading from the files fails.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public MyKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyPair = Helper.readKeyPair(publicKeyFile, privateKeyFile, ALGORITHM);
    }

    /**
     * Loads only an existing RSA Public Key from a stored Base64 string file.
     * 
     * @param publicKeyFile Path to the public key PEM file.
     * @throws IOException If reading from the file fails.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public MyKeyPair(String publicKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = Helper.readPublicKey(publicKeyFile, ALGORITHM);
        this.keyPair = new KeyPair(publicKey, null);
    }

    /**
     * Creates a MyKeyPair instance from an existing PublicKey.
     * 
     * @param publicKey The PublicKey to use.
     */
    public MyKeyPair(PublicKey publicKey) {
        this.keyPair = new KeyPair(publicKey, null);
    }

    /**
     * Manually sets the internal KeyPair instance.
     * 
     * @param keyPair The KeyPair instance to use.
     */
    public MyKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Creates a new instance of MyKeyPair that only contains the public key.
     * This is useful for safely sharing public keys with others without exposing the private key.
     * 
     * @return A new MyKeyPair instance containing only the public key.
     */
    public MyKeyPair getPublicOnly() {
        return new MyKeyPair(getPublicKey());
    }

    /**
     * Manually sets the internal KeyPair instance.
     * 
     * @param keyPair The KeyPair instance to set.
     */
    @Override
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    /**
     * Decrypts a message using this instance's Private Key.
     * Only the owner of the Private Key can read data that was encrypted with their Public Key.
     * 
     * @param encrypted The base64 encoded ciphertext to decrypt.
     * @return The decrypted plaintext message as a String.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws NoSuchPaddingException If the requested padding is not available.
     * @throws InvalidKeyException If the private key is invalid.
     * @throws IllegalBlockSizeException If the block size is invalid.
     * @throws BadPaddingException If the padding is incorrect.
     * @throws IllegalStateException If the private key is missing (e.g., this is a public-key-only instance).
     */
    @Override
    public String decrypt(String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PrivateKey privateKey = getPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key is missing. This operation requires the private key.");
        }
        byte[] decodedBytes = Helper.b64Decode(encrypted);
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    /**
     * Encrypts a message using this instance's Public Key.
     * Anyone can use the Public Key to encrypt a message, but only the Private Key owner can decrypt it.
     * 
     * @param message The plaintext message to encrypt.
     * @return The encrypted ciphertext as a base64 encoded String.
     * @throws NoSuchAlgorithmException If the RSA algorithm is not available.
     * @throws NoSuchPaddingException If the requested padding is not available.
     * @throws InvalidKeyException If the public key is invalid.
     * @throws IllegalBlockSizeException If the block size is invalid.
     * @throws BadPaddingException If padding fails.
     */
    @Override
    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        PublicKey publicKey = getPublicKey();
        if (publicKey == null) {
            throw new IllegalStateException("Public key is missing.");
        }
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(messageBytes);
        return Helper.b64Encode(encryptedBytes);
    }

    /**
     * Verifies a digital signature using this instance's Public Key.
     * This proves that the message was signed by the owner of the corresponding Private Key and hasn't been altered.
     * 
     * @param message The original message that was signed.
     * @param signature The base64 encoded digital signature to verify.
     * @return true if the signature is valid; false otherwise.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the public key is invalid.
     * @throws SignatureException If signature verification fails.
     * @throws InvalidAlgorithmParameterException If the PSS parameters are invalid.
     */
    @Override
    public boolean isSignatureValid(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        PublicKey publicKey = getPublicKey();
        if (publicKey == null) {
            throw new IllegalStateException("Public key is missing.");
        }
        byte[] signatureBytes = Helper.b64Decode(signature);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        Signature signatureVerifier = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signatureVerifier.setParameter(pssParameterSpec);
        signatureVerifier.initVerify(publicKey);
        signatureVerifier.update(messageBytes);
        return signatureVerifier.verify(signatureBytes);

    }

    /**
     * Creates a digital signature for a message using this instance's Private Key.
     * A signature proves authenticity (who sent it) and integrity (it wasn't tampered with).
     * 
     * @param message The message to sign.
     * @return The digital signature as a base64 encoded String.
     * @throws NoSuchAlgorithmException If the signature algorithm is not available.
     * @throws InvalidKeyException If the private key is invalid.
     * @throws SignatureException If signing fails.
     * @throws InvalidAlgorithmParameterException If the PSS parameters are invalid.
     * @throws IllegalStateException If the private key is missing (e.g., this is a public-key-only instance).
     */
    @Override
    public String sign(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        PrivateKey privateKey = getPrivateKey();
        if (privateKey == null) {
            throw new IllegalStateException("Private key is missing. This operation requires the private key.");
        }
        Signature signature = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signature.setParameter(pssParameterSpec);
        signature.initSign(privateKey);
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        signature.update(messageBytes);
        byte[] signedBytes = signature.sign();
        return Helper.b64Encode(signedBytes);
    }

    /**
     * Returns the underlying Java PrivateKey object.
     * 
     * @return The private key from the internal KeyPair, or null if it's missing.
     */
    @Override
    public PrivateKey getPrivateKey() {
        return (keyPair != null) ? keyPair.getPrivate() : null;
    }

    /**
     * Returns the underlying Java PublicKey object.
     * 
     * @return The public key from the internal KeyPair, or null if it's missing.
     */
    @Override
    public PublicKey getPublicKey() {
        return (keyPair != null) ? keyPair.getPublic() : null;
    }


    /**
     * Generates a short, unique identifier (fingerprint) for the Public Key.
     * Useful for comparing keys or displaying them in logs without printing the massive raw key string.
     * 
     * @return A hexadecimal string representing the Public Key's ID.
     * @throws NoSuchAlgorithmException If the hash algorithm for calculation is not available.
     */
    @Override
    public String getPublicKeyId() throws NoSuchAlgorithmException {
        PublicKey publicKey = getPublicKey();
        if (publicKey == null) {
            return "N/A";
        }
        KeySpec publicKeySpec = getKeySpec(publicKey);
        return calculateKeyId(publicKeySpec);
    }

    /**
     * Generates a short, unique identifier (fingerprint) for the Private Key.
     * 
     * @return A hexadecimal string representing the Private Key's ID, or "N/A" if missing.
     * @throws NoSuchAlgorithmException If the hash algorithm for calculation is not available.
     */
    @Override
    public String getPrivateKeyId() throws NoSuchAlgorithmException {
        PrivateKey privateKey = getPrivateKey();
        if (privateKey == null) {
            return "N/A";
        }
        KeySpec privateKeySpec = getKeySpec(privateKey);
        return calculateKeyId(privateKeySpec);
    }

    /**
     * Extracts the mathematical properties (modulus and exponent) that make up an RSA key.
     * 
     * @param key The RSA key (Public or Private) to extract specs from.
     * @return The KeySpec object for the given key.
     * @throws IllegalArgumentException If the key type is not supported.
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
     * 
     * @param keySpec The specification of the RSA key.
     * @return A hexadecimal fingerprint String.
     * @throws NoSuchAlgorithmException If the hash algorithm is not available.
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
        byte[] combinedBytes = Helper.appendByteArray(modulus.toByteArray(), exponent.toByteArray());
        MessageDigest sha256 = MessageDigest.getInstance(HASH);
        byte[] hash = sha256.digest(combinedBytes);
        byte[] keyId = new byte[8];
        System.arraycopy(hash, 0, keyId, 0, 8);
        return Helper.bytesToHexString(keyId).toUpperCase();
    }
}
