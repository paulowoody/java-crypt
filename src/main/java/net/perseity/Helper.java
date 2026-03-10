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

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;

/**
 * Utility class providing common Base64 encoding/decoding and PEM file operations.
 */
public class Helper {
    public static final String CERT_FOOTER = "-----END CERTIFICATE-----";
    public static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----";

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
     * Reads an X.509 Certificate from a PEM file.
     */
    public static java.security.cert.X509Certificate readCert(String certFile) throws IOException, java.security.cert.CertificateException {
        String certString = loadKey(certFile);
        byte[] certBytes = b64Decode(certString);
        java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    /**
     * Saves an X.509 Certificate to a PEM file.
     */
    public static void saveCert(java.security.cert.X509Certificate cert, String filename) throws IOException, java.security.cert.CertificateEncodingException {
        writePem(filename, CERT_HEADER, CERT_FOOTER, cert.getEncoded());
    }

    /**
     * Serializes a single cryptographic Key into PEM (Privacy-Enhanced Mail) format 
     * and writes it to a file. PEM format wraps Base64-encoded data in explicit header and footer lines.
     */
    private static void saveKey(Key key, String filename) throws IOException {
        writePem(filename, getPemHeader(key), getPemFooter(key), key.getEncoded());
    }

    /**
     * Shared utility to write Base64 encoded data with PEM headers and footers to a file.
     */
    private static void writePem(String filename, String header, String footer, byte[] data) throws IOException {
        try (Writer fileWriter = new FileWriter(filename)) {
            Base64.Encoder mimeEncoder = Base64.getMimeEncoder(64, System.lineSeparator().getBytes());
            String encodedData = mimeEncoder.encodeToString(data);

            fileWriter.write(header);
            fileWriter.write(System.lineSeparator());
            fileWriter.write(encodedData);
            fileWriter.write(System.lineSeparator());
            fileWriter.write(footer);
        }
    }

    /**
     * Reads a matching Public and Private key from disk.
     */
    public static KeyPair readKeyPair(String publicKeyFile, String privateKeyFile, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyString = loadKey(publicKeyFile);
        String privateKeyString = loadKey(privateKeyFile);

        byte[] publicKeyBytes = b64Decode(publicKeyString);
        byte[] privateKeyBytes = b64Decode(privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Helper method to populate an existing AsymmetricCipher instance with keys loaded from disk.
     */
    public static void loadKeyPair(AsymmetricCipher cipher, String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        cipher.setKeyPair(readKeyPair(publicKeyFile, privateKeyFile, cipher.getAlgorithm()));
    }

    /**
     * Saves an AsymmetricCipher's public and private keys to separate PEM files on disk.
     */
    public static void saveKeyPair(AsymmetricCipher cipher, String publicKeyFile, String privateKeyFile) throws IOException {
        saveKey(cipher.getPublicKey(), publicKeyFile);
        saveKey(cipher.getPrivateKey(), privateKeyFile);
    }

    /**
     * Determines the appropriate PEM header based on whether the key is Public or Private.
     */
    private static String getPemHeader(Key key) {
        return (key instanceof PublicKey) ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    }

    /**
     * Determines the appropriate PEM footer based on whether the key is Public or Private.
     */
    private static String getPemFooter(Key key) {
        return (key instanceof PublicKey) ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";
    }

    /**
     * Strips the PEM headers, footers, and whitespace/newlines from a file's content
     * to isolate the raw Base64 payload.
     */
    private static String extractBase64Content(String pemContent) {
        // Remove headers and footers using regex
        String base64Content = pemContent.replaceAll("-----BEGIN.*?-----", "")
                                         .replaceAll("-----END.*?-----", "");

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

    /**
     * Saves a MimeMultipart to a file on disk.
     */
    public static void saveMimeMultipart(MimeMultipart multipart, String filename) throws IOException, MessagingException {
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(filename)) {
            multipart.writeTo(fos);
        }
    }

    /**
     * Loads a MimeMultipart from a file on disk.
     */
    public static MimeMultipart loadMimeMultipart(String filename) throws IOException, MessagingException {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(filename)) {
            return new MimeMultipart(new ByteArrayDataSource(fis, "multipart/mixed"));
        }
    }

    /**
     * Registers MailcapCommandMap to fix missing content handlers when running from a fat jar.
     */
    public static void setupMailcap() {
        MailcapCommandMap mc = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        mc.addMailcap("text/plain;; x-java-content-handler=com.sun.mail.handlers.text_plain");
        mc.addMailcap("multipart/*;; x-java-content-handler=com.sun.mail.handlers.multipart_mixed");
        CommandMap.setDefaultCommandMap(mc);
    }
}
