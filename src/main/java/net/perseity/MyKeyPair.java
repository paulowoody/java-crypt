package net.perseity;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.HexFormat;

public class MyKeyPair {
    private static final int SIZE = 1024;
    private static final String ALGORITHM = "RSASSA-PSS";
    private static final String HASH = "SHA-256";
    private static final String MASK_GEN_FN = "MGF1";
    private static final String CYPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String PRIVATE_HEADER = String.format("-----BEGIN %s PRIVATE KEY-----", ALGORITHM);
    private static final String PRIVATE_FOOTER = String.format("-----END %s PRIVATE KEY-----", ALGORITHM);
    private static final String PUBLIC_HEADER = String.format("-----BEGIN %s PUBLIC KEY-----", ALGORITHM);
    private static final String PUBLIC_FOOTER = String.format("-----END %s PUBLIC KEY-----", ALGORITHM);
    private java.security.KeyPair key;

    public MyKeyPair() throws NoSuchAlgorithmException {
        Security.setProperty("crypto.policy", "unlimited");
        KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM);
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        generator.initialize(SIZE, random);
        key = generator.generateKeyPair();
    }

    public MyKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        loadKeys(publicKeyFile, privateKeyFile);
    }

    public String getDecrypted(String encrypted) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decodedBytes = Util.b64Decode(encrypted);
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    public String getEncrypted(String message) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CYPHER);
        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(messageBytes);
        return Util.b64Encode(encryptedBytes);
    }

    public boolean isSignatureValid(String message, String signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        byte[] signatureBytes = Util.b64Decode(signature);
        byte[] messageBytes = message.getBytes();
        Signature signatureVerifier = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signatureVerifier.setParameter(pssParameterSpec);
        signatureVerifier.initVerify(getPublicKey());
        signatureVerifier.update(messageBytes);
        return signatureVerifier.verify(signatureBytes);

    }

    public String getSignature(String message) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance(ALGORITHM);
        MGF1ParameterSpec mgf1Spec = MGF1ParameterSpec.SHA256;
        PSSParameterSpec pssParameterSpec = new PSSParameterSpec(HASH, MASK_GEN_FN, mgf1Spec, 32, 1); // Adjust salt length if needed
        signature.setParameter(pssParameterSpec);
        signature.initSign(getPrivateKey());
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        signature.update(messageBytes);
        byte[] signedBytes = signature.sign();
        return Util.b64Encode(signedBytes);
    }

    public PrivateKey getPrivateKey() {
        return key.getPrivate();
    }

    public PublicKey getPublicKey() {
        return key.getPublic();
    }

    public void saveKeys(String publicKeyFile, String privateKeyFile) throws IOException {
        saveKey(getPublicKey(), publicKeyFile);
        saveKey(getPrivateKey(), privateKeyFile);
    }

    private static void saveKey(Key key, String filename) throws IOException {
        try (Writer keyFile = new FileWriter(filename)) {
            Base64.Encoder mimeEncoder = Base64.getMimeEncoder(64, System.lineSeparator().getBytes());
            String encodedKey = mimeEncoder.encodeToString(key.getEncoded());

            // Write the header, followed by a newline
            keyFile.write(getPemHeader(key));
            keyFile.write(System.lineSeparator());

            // Write the Base64-encoded content
            keyFile.write(encodedKey);

            // Write the footer, followed by a newline
            keyFile.write(System.lineSeparator());
            keyFile.write(getPemFooter(key));
        }
    }

    private static String getPemHeader(Object key) {
        return (key instanceof PublicKey) ? PUBLIC_HEADER : PRIVATE_HEADER;
    }

    private static String getPemFooter(Object key) {
        return (key instanceof PublicKey) ? PUBLIC_FOOTER : PRIVATE_FOOTER;
    }

    public void loadKeys(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyString = loadKey(publicKeyFile);
        String privateKeyString = loadKey(privateKeyFile);

        byte[] publicKeyBytes = Util.b64Decode(publicKeyString);
        byte[] privateKeyBytes = Util.b64Decode(privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        key = new java.security.KeyPair(publicKey, privateKey);
    }


    private static String loadKey(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        String pemContent = new String(keyBytes);
        return extractBase64Content(pemContent);
    }

    private static String extractBase64Content(String pemContent) {
        // Remove headers and footers
        String base64Content = pemContent.replace(PRIVATE_HEADER, "")
                                         .replace(PRIVATE_FOOTER, "")
                                         .replace(PUBLIC_HEADER, "")
                                         .replace(PUBLIC_FOOTER, "");

        // Normalize line endings and remove leading and trailing whitespace
        return base64Content.replace("\r\n", "").replace("\n", "").trim();
    }

    public String getPublicKeyId() throws NoSuchAlgorithmException {
        KeySpec publicKeySpec = getKeySpec(key.getPublic());
        return computeKeyId(publicKeySpec);
    }

    public String getPrivateKeyId() throws NoSuchAlgorithmException {
        KeySpec privateKeySpec = getKeySpec(key.getPrivate());
        return computeKeyId(privateKeySpec);
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

    private String computeKeyId(KeySpec keySpec) throws NoSuchAlgorithmException {
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
