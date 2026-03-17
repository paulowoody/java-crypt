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
 * This class is not intended to be instantiated.
 */
public class Helper {
    /**
     * The standard PEM footer for X.509 certificates.
     */
    public static final String CERT_FOOTER = "-----END CERTIFICATE-----";

    /**
     * The standard PEM header for X.509 certificates.
     */
    public static final String CERT_HEADER = "-----BEGIN CERTIFICATE-----";

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private Helper() {
        // Utility class
    }

    /**
     * Standard Base64 Encoding (RFC 4648). Used primarily for standard cryptography payloads.
     * 
     * @param byteArray The byte array to encode.
     * @return The base64 encoded String.
     */
    public static String b64Encode(byte[] byteArray) {
        Base64.Encoder encoder = Base64.getEncoder();
        return new String(encoder.encode(byteArray), StandardCharsets.UTF_8);
    }

    /**
     * Standard Base64 Decoding.
     * 
     * @param string The base64 encoded String to decode.
     * @return The decoded byte array.
     */
    public static byte[] b64Decode(String string) {
        Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * URL-Safe Base64 Encoding without padding (RFC 4648 Sec 5). 
     * Required for JWTs so tokens can be passed safely in URLs without breaking.
     * 
     * @param byteArray The byte array to encode.
     * @return The URL-safe base64 encoded String.
     */
    public static String b64UrlEncode(byte[] byteArray) {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        return encoder.encodeToString(byteArray);
    }

    /**
     * URL-Safe Base64 Decoding.
     * 
     * @param string The URL-safe base64 encoded String to decode.
     * @return The decoded byte array.
     */
    public static byte[] b64UrlDecode(String string) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        return decoder.decode(string.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Reads an X.509 Certificate from a PEM file.
     * 
     * @param certFile The path to the PEM file containing the certificate.
     * @return The loaded X509Certificate object.
     * @throws IOException If reading from the file fails.
     * @throws java.security.cert.CertificateException If the certificate cannot be parsed.
     */
    public static java.security.cert.X509Certificate readCert(String certFile) throws IOException, java.security.cert.CertificateException {
        String certString = loadKey(certFile);
        byte[] certBytes = b64Decode(certString);
        java.security.cert.CertificateFactory factory = java.security.cert.CertificateFactory.getInstance("X.509");
        return (java.security.cert.X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(certBytes));
    }

    /**
     * Saves an X.509 Certificate to a PEM file.
     * 
     * @param cert The X509Certificate to save.
     * @param filename The path where the certificate should be saved.
     * @throws IOException If writing to the file fails.
     * @throws java.security.cert.CertificateEncodingException If encoding the certificate fails.
     */
    public static void saveCert(java.security.cert.X509Certificate cert, String filename) throws IOException, java.security.cert.CertificateEncodingException {
        writePem(filename, CERT_HEADER, CERT_FOOTER, cert.getEncoded());
    }

    /**
     * Serializes a single cryptographic Key into PEM (Privacy-Enhanced Mail) format 
     * and writes it to a file. PEM format wraps Base64-encoded data in explicit header and footer lines.
     * 
     * @param key The Key to save.
     * @param filename The path where the key should be saved.
     * @throws IOException If writing to the file fails.
     */
    private static void saveKey(Key key, String filename) throws IOException {
        writePem(filename, getPemHeader(key), getPemFooter(key), key.getEncoded());
    }

    /**
     * Shared utility to write Base64 encoded data with PEM headers and footers to a file.
     * 
     * @param filename The path where the file should be written.
     * @param header The PEM header line.
     * @param footer The PEM footer line.
     * @param data The raw byte data to be encoded and wrapped.
     * @throws IOException If writing to the file fails.
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
     * Reads a Public key from disk.
     * 
     * @param publicKeyFile Path to the public key PEM file.
     * @param algorithm The name of the algorithm (e.g. "RSA").
     * @return A PublicKey object loaded from the file.
     * @throws IOException If reading from the file fails.
     * @throws NoSuchAlgorithmException If the specified algorithm is not supported.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public static PublicKey readPublicKey(String publicKeyFile, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String publicKeyString = loadKey(publicKeyFile);
        byte[] publicKeyBytes = b64Decode(publicKeyString);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
    }

    /**
     * Reads a matching Public and Private key from disk.
     * 
     * @param publicKeyFile Path to the public key PEM file.
     * @param privateKeyFile Path to the private key PEM file.
     * @param algorithm The name of the algorithm (e.g. "RSA").
     * @return A KeyPair object containing both the loaded public and private keys.
     * @throws IOException If reading from either file fails.
     * @throws NoSuchAlgorithmException If the specified algorithm is not supported.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public static KeyPair readKeyPair(String publicKeyFile, String privateKeyFile, String algorithm) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = readPublicKey(publicKeyFile, algorithm);
        String privateKeyString = loadKey(privateKeyFile);
        byte[] privateKeyBytes = b64Decode(privateKeyString);

        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Helper method to populate an existing AsymmetricCipher instance with a public key loaded from disk.
     * 
     * @param cipher The AsymmetricCipher instance to load the key into.
     * @param publicKeyFile Path to the public key PEM file.
     * @throws IOException If reading from the file fails.
     * @throws NoSuchAlgorithmException If the algorithm used by the cipher is not supported.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public static void loadPublicKey(AsymmetricCipher cipher, String publicKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey publicKey = readPublicKey(publicKeyFile, cipher.getAlgorithm());
        cipher.setKeyPair(new KeyPair(publicKey, null));
    }

    /**
     * Helper method to populate an existing AsymmetricCipher instance with keys loaded from disk.
     * 
     * @param cipher The AsymmetricCipher instance to load keys into.
     * @param publicKeyFile Path to the public key PEM file.
     * @param privateKeyFile Path to the private key PEM file.
     * @throws IOException If reading from either file fails.
     * @throws NoSuchAlgorithmException If the algorithm used by the cipher is not supported.
     * @throws InvalidKeySpecException If the key specifications are invalid.
     */
    public static void loadKeyPair(AsymmetricCipher cipher, String publicKeyFile, String privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        cipher.setKeyPair(readKeyPair(publicKeyFile, privateKeyFile, cipher.getAlgorithm()));
    }

    /**
     * Saves an AsymmetricCipher's public and private keys to separate PEM files on disk.
     * 
     * @param cipher The AsymmetricCipher instance whose keys should be saved.
     * @param publicKeyFile Path where the public key should be saved.
     * @param privateKeyFile Path where the private key should be saved.
     * @throws IOException If writing to either file fails.
     */
    public static void saveKeyPair(AsymmetricCipher cipher, String publicKeyFile, String privateKeyFile) throws IOException {
        saveKey(cipher.getPublicKey(), publicKeyFile);
        saveKey(cipher.getPrivateKey(), privateKeyFile);
    }

    /**
     * Determines the appropriate PEM header based on whether the key is Public or Private.
     * 
     * @param key The Key to check.
     * @return The corresponding PEM header String.
     */
    private static String getPemHeader(Key key) {
        return (key instanceof PublicKey) ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
    }

    /**
     * Determines the appropriate PEM footer based on whether the key is Public or Private.
     * 
     * @param key The Key to check.
     * @return The corresponding PEM footer String.
     */
    private static String getPemFooter(Key key) {
        return (key instanceof PublicKey) ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";
    }

    /**
     * Strips the PEM headers, footers, and whitespace/newlines from a file's content
     * to isolate the raw Base64 payload.
     * 
     * @param pemContent The full content of a PEM file.
     * @return The isolated Base64 encoded payload.
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
     * 
     * @param filePath The path to the PEM file.
     * @return The Base64 encoded content of the key.
     * @throws IOException If reading from the file fails.
     */
    private static String loadKey(String filePath) throws IOException {
        byte[] keyBytes = Files.readAllBytes(Paths.get(filePath));
        String pemContent = new String(keyBytes);
        return extractBase64Content(pemContent);
    }

    /**
     * Saves a MimeMultipart to a file on disk.
     * 
     * @param multipart The MimeMultipart content to save.
     * @param filename The path where the content should be saved.
     * @throws IOException If writing to the file fails.
     * @throws MessagingException If a messaging error occurs while writing the multipart.
     */
    public static void saveMimeMultipart(MimeMultipart multipart, String filename) throws IOException, MessagingException {
        try (java.io.FileOutputStream fos = new java.io.FileOutputStream(filename)) {
            multipart.writeTo(fos);
        }
    }

    /**
     * Loads a MimeMultipart from a file on disk.
     * 
     * @param filename The path to the file to load.
     * @return The loaded MimeMultipart object.
     * @throws IOException If reading from the file fails.
     * @throws MessagingException If a messaging error occurs while parsing the multipart.
     */
    public static MimeMultipart loadMimeMultipart(String filename) throws IOException, MessagingException {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(filename)) {
            return new MimeMultipart(new ByteArrayDataSource(fis, "multipart/mixed"));
        }
    }

    /**
     * Registers MailcapCommandMap to fix missing content handlers when running from a fat jar.
     * This is necessary because some environments do not automatically discover S/MIME handlers.
     */
    public static void setupMailcap() {
        MailcapCommandMap mc = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        mc.addMailcap("text/plain;; x-java-content-handler=com.sun.mail.handlers.text_plain");
        mc.addMailcap("multipart/*;; x-java-content-handler=com.sun.mail.handlers.multipart_mixed");
        CommandMap.setDefaultCommandMap(mc);
    }

    /**
     * Helper method to concatenate two byte arrays.
     * 
     * @param a The first byte array.
     * @param b The second byte array.
     * @return The combined byte array.
     */
    public static byte[] appendByteArray(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    /**
     * Converts a byte array into a colon-separated hexadecimal string format (e.g., "1A:2B:3C").
     * 
     * @param bytes The byte array to convert.
     * @return The formatted hexadecimal String.
     */
    public static String bytesToHexString(byte[] bytes) {
        java.util.HexFormat hexFormat = java.util.HexFormat.ofDelimiter(":");
        return hexFormat.formatHex(bytes).toUpperCase();
    }
}
