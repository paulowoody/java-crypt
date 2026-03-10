package net.perseity;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.activation.CommandMap;
import javax.activation.MailcapCommandMap;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class HelperTest {

    private Path tempDir;

    @BeforeEach
    void setUp() throws IOException {
        tempDir = Files.createTempDirectory("helper-test");
    }

    @AfterEach
    void tearDown() throws IOException {
        try (java.util.stream.Stream<Path> pathStream = Files.walk(tempDir)) {
            pathStream.sorted(java.util.Comparator.reverseOrder())
                      .map(Path::toFile)
                      .forEach(file -> {
                          if (!file.delete()) {
                              file.deleteOnExit();
                          }
                      });
        }
    }

    @Test
    void testStandardBase64() {
        String originalText = "Hello World! @#$%^&*()_+";
        byte[] originalBytes = originalText.getBytes(StandardCharsets.UTF_8);

        String encoded = Helper.b64Encode(originalBytes);
        byte[] decodedBytes = Helper.b64Decode(encoded);
        String decodedText = new String(decodedBytes, StandardCharsets.UTF_8);

        assertNotEquals(originalText, encoded);
        assertEquals(originalText, decodedText);
    }

    @Test
    void testUrlSafeBase64() {
        // A byte array that produces + and / in standard base64: { (byte)255, (byte)239, (byte)254 } => "/+/+" standard, expects padding.
        byte[] originalBytes = { (byte) 255, (byte) 239, (byte) 254 };
        
        String urlEncoded = Helper.b64UrlEncode(originalBytes);

        // URL safe should not have these chars
        assertFalse(urlEncoded.contains("+"));
        assertFalse(urlEncoded.contains("/"));
        assertFalse(urlEncoded.contains("=")); // padding is removed

        byte[] decodedBytes = Helper.b64UrlDecode(urlEncoded);
        assertArrayEquals(originalBytes, decodedBytes);
    }

    @Test
    void testSaveAndLoadCertAndKeyPair() throws Exception {
        MyKeyPair originalKeyPair = new MyKeyPair();
        MyTLSCert originalCert = new MyTLSCert(originalKeyPair, "CN=test", 1);

        Path certFile = tempDir.resolve("test.pem");
        Path pubKeyFile = tempDir.resolve("public.pem");
        Path privKeyFile = tempDir.resolve("private.pem");

        // Save to temporary files
        Helper.saveCert(originalCert.getCertificate(), certFile.toString());
        Helper.saveKeyPair(originalKeyPair, pubKeyFile.toString(), privKeyFile.toString());

        assertTrue(Files.exists(certFile));
        assertTrue(Files.exists(pubKeyFile));
        assertTrue(Files.exists(privKeyFile));

        // Load back from temporary files
        X509Certificate loadedCert = Helper.readCert(certFile.toString());
        KeyPair loadedKeyPair = Helper.readKeyPair(pubKeyFile.toString(), privKeyFile.toString(), MyKeyPair.ALGORITHM);

        assertEquals(originalCert.getCertificate(), loadedCert);
        assertArrayEquals(originalKeyPair.getPublicKey().getEncoded(), loadedKeyPair.getPublic().getEncoded());
        assertArrayEquals(originalKeyPair.getPrivateKey().getEncoded(), loadedKeyPair.getPrivate().getEncoded());
        
        // Test loadKeyPair method that mutates an existing instance
        MyKeyPair targetKeyPair = new MyKeyPair();
        Helper.loadKeyPair(targetKeyPair, pubKeyFile.toString(), privKeyFile.toString());
        assertArrayEquals(originalKeyPair.getPublicKey().getEncoded(), targetKeyPair.getPublicKey().getEncoded());
    }

    @Test
    void testSaveAndLoadMimeMultipart() throws Exception {
        Path emlFile = tempDir.resolve("test.eml");

        MimeMultipart originalMultipart = new MimeMultipart();
        MimeBodyPart part = new MimeBodyPart();
        part.setText("Test Email Body");
        originalMultipart.addBodyPart(part);

        Helper.saveMimeMultipart(originalMultipart, emlFile.toString());
        assertTrue(Files.exists(emlFile));

        MimeMultipart loadedMultipart = Helper.loadMimeMultipart(emlFile.toString());
        assertEquals(1, loadedMultipart.getCount());
        
        MimeBodyPart loadedPart = (MimeBodyPart) loadedMultipart.getBodyPart(0);
        String loadedText;
        try (java.io.InputStream is = loadedPart.getInputStream()) {
            loadedText = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
        }
        assertEquals("Test Email Body", loadedText);
    }

    @Test
    void testSetupMailcap() {
        Helper.setupMailcap();
        CommandMap defaultMap = CommandMap.getDefaultCommandMap();
        assertInstanceOf(MailcapCommandMap.class, defaultMap);
        
        MailcapCommandMap mailcapMap = (MailcapCommandMap) defaultMap;
        String[] mimetypes = mailcapMap.getMimeTypes();
        
        boolean hasTextPlain = false;
        boolean hasMultipart = false;
        for (String type : mimetypes) {
            if ("text/plain".equals(type)) hasTextPlain = true;
            if ("multipart/*".equals(type)) hasMultipart = true;
        }
        
        assertTrue(hasTextPlain);
        assertTrue(hasMultipart);
    }
}
