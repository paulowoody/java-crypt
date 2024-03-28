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

public class MyKeyPair {
    public static final String ALGORITHM = "RSASSA-PSS";
    private static final int SIZE = 1024;
    private static final String HASH = "SHA-256";
    private static final String MASK_GEN_FN = "MGF1";
    private static final String CYPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    private java.security.KeyPair keyPair;

    public MyKeyPair() throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(SIZE, random);
        keyPair = generator.generateKeyPair();
    }

    public MyKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Helper.loadKeyPair(this, publicKeyFile, privateKeyFile);
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public String decrypt(String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decodedBytes = Helper.b64Decode(encrypted);
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public String encrypt(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(messageBytes);
        return Helper.b64Encode(encryptedBytes);
    }

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

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }


    public String getPublicKeyId() throws NoSuchAlgorithmException {
        KeySpec publicKeySpec = getKeySpec(keyPair.getPublic());
        return calculateKeyId(publicKeySpec);
    }

    public String getPrivateKeyId() throws NoSuchAlgorithmException {
        KeySpec privateKeySpec = getKeySpec(keyPair.getPrivate());
        return calculateKeyId(privateKeySpec);
    }

    private KeySpec getKeySpec(Key key) {
        if (key instanceof RSAPublicKey publicKey) {
            return new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getPublicExponent());
        } else if (key instanceof RSAPrivateKey privateKey) {
            return new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getPrivateExponent());
        } else {
            throw new IllegalArgumentException("Unsupported key type");
        }
    }

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

    private byte[] appendByteArray(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private String bytesToHexString(byte[] bytes) {
        HexFormat hexFormat = HexFormat.ofDelimiter(":");
        return hexFormat.formatHex(bytes).toUpperCase();
    }
}
