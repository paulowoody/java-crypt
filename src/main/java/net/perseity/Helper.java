package net.perseity;

import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class providing common Base64 encoding/decoding and PEM file operations.
 */
public class Helper {
    public static final String PUBLIC_FOOTER = String.format("-----END %s PUBLIC KEY-----", MyKeyPair.ALGORITHM);
    public static final String PUBLIC_HEADER = String.format("-----BEGIN %s PUBLIC KEY-----", MyKeyPair.ALGORITHM);
    public static final String PRIVATE_FOOTER = String.format("-----END %s PRIVATE KEY-----", MyKeyPair.ALGORITHM);
    public static final String PRIVATE_HEADER = String.format("-----BEGIN %s PRIVATE KEY-----", MyKeyPair.ALGORITHM);

    /**
     * Standard Base64 Encoding (RFC 4648). Used primarily for standard cryptography payloads.
     */
    public static String b64Encode(byte[] byteArray) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new String(encoder.encode(byteArray), StandardCharsets.UTF_8);
    }

    /**
     * Standard Base64 Decoding.
     */
    public static byte[] b64Decode(String string) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * URL-Safe Base64 Encoding without padding (RFC 4648 Sec 5). 
     * Required for JWTs so tokens can be passed safely in URLs without breaking.
     */
    public static String b64UrlEncode(byte[] byteArray) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(byteArray);
    }

    /**
     * URL-Safe Base64 Decoding.
     */
    public static byte[] b64UrlDecode(String string) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        return decoder.decode(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Reads a matching Public and Private key from disk.
     */
    public static KeyPair readKeyPair(String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyString = loadKey(publicKeyFile);
        String privateKeyString = loadKey(privateKeyFile);

        byte[] publicKeyBytes = b64Decode(publicKeyString);
        byte[] privateKeyBytes = b64Decode(privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance(MyKeyPair.ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Helper method to populate an existing MyKeyPair instance with keys loaded from disk.
     */
    public static void loadKeyPair(MyKeyPair keyPair, String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        keyPair.setKeyPair(readKeyPair(publicKeyFile, privateKeyFile));
    }

    /**
     * Saves a KeyPair's public and private keys to separate PEM files on disk.
     */
    public static void saveKeyPair(MyKeyPair keyPair, String publicKeyFile, String privateKeyFile) throws IOException {
        saveKey(keyPair.getPublicKey(), publicKeyFile);
        saveKey(keyPair.getPrivateKey(), privateKeyFile);
    }

    /**
     * Serializes a single cryptographic Key into PEM (Privacy-Enhanced Mail) format 
     * and writes it to a file. PEM format wraps Base64-encoded data in explicit header and footer lines.
     */
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

    /**
     * Determines the appropriate PEM header based on whether the key is Public or Private.
     */
    private static String getPemHeader(Object key) {
        return (key instanceof PublicKey) ? PUBLIC_HEADER : PRIVATE_HEADER;
    }

    /**
     * Determines the appropriate PEM footer based on whether the key is Public or Private.
     */
    private static String getPemFooter(Object key) {
        return (key instanceof PublicKey) ? PUBLIC_FOOTER : PRIVATE_FOOTER;
    }

    /**
     * Strips the PEM headers, footers, and whitespace/newlines from a file's content
     * to isolate the raw Base64 payload.
     */
    private static String extractBase64Content(String pemContent) {
        // Remove headers and footers
        String base64Content = pemContent.replace(PRIVATE_HEADER, "").replace(PRIVATE_FOOTER, "").replace(PUBLIC_HEADER, "").replace(PUBLIC_FOOTER, "");

        // Normalize line endings and remove leading and trailing whitespace
        return base64Content.replace("\r\n", "").replace("\n", "").trim();
    }

    /**
     * Reads a PEM file from disk and returns the inner Base64-encoded key string.
     */
    private static String loadKey(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        String pemContent = new String(keyBytes);
        return extractBase64Content(pemContent);
    }
}
