package net.perseity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MyKeyPairTest {
    private static final Logger logger = LogManager.getLogger(MyKeyPairTest.class);
    private static MyKeyPair myKey;

    @TempDir
    static Path tempDir;

    @BeforeAll
    public void setup() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        // Generate ephemeral keys for testing
        MyKeyPair originalKey = new MyKeyPair();
        String pubPath = tempDir.resolve("myKey.pub").toString();
        String privPath = tempDir.resolve("myKey.key").toString();
        Helper.saveKeyPair(originalKey, pubPath, privPath);

        // Load the keys back from files to test the file-loading constructor
        myKey = new MyKeyPair(pubPath, privPath);
    }

    @AfterAll
    public void tearDown() {
        logger.info("Finished.");
    }

    @Test
    void constructorDoesNotThrowError() {
        assertDoesNotThrow(() -> new MyKeyPair());
    }

    @Test
    void getDecrypted() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String expected = "Hello, World";
        String encrypted = myKey.encrypt(expected);
        String decrypted = myKey.decrypt(encrypted);
        assertEquals(expected, decrypted);
    }

    @Test
    void getEncrypted() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String message = "Hello, World";
        String encrypted = myKey.encrypt(message);
        // RSA OAEP encryption length depends on the key size. 1024-bit key produces 128 bytes, 
        // which when base64 encoded is around 172 characters.
        assertTrue(encrypted.length() > 100);
    }

    @Test
    void isSignatureValid() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String message = "Hello, World";
        String signature = myKey.sign(message);
        assertTrue(myKey.isSignatureValid(message, signature));
    }

    @Test
    void getSigned() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String signature = myKey.sign("Hello, World");
        assertTrue(signature.length() > 100);
    }

    @Test
    void getPrivateKey() {
        assertNotNull(myKey.getPrivateKey());
    }

    @Test
    void getPublicKey() {
        assertNotNull(myKey.getPublicKey());
    }

    @Test
    void getPublicKeyId() throws NoSuchAlgorithmException {
        String id = myKey.getPublicKeyId();
        assertNotNull(id);
        assertTrue(id.matches("^([0-9A-F]{2}:){7}[0-9A-F]{2}$"));
    }

    @Test
    void getPrivateKeyId() throws NoSuchAlgorithmException {
        String id = myKey.getPrivateKeyId();
        assertNotNull(id);
        assertTrue(id.matches("^([0-9A-F]{2}:){7}[0-9A-F]{2}$"));
    }

    @Test
    void testPublicOnlyInstance() throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, SignatureException {
        MyKeyPair publicOnly = myKey.getPublicOnly();
        
        assertNotNull(publicOnly.getPublicKey());
        assertNull(publicOnly.getPrivateKey());
        assertEquals("N/A", publicOnly.getPrivateKeyId());
        assertEquals(myKey.getPublicKeyId(), publicOnly.getPublicKeyId());

        // Test encryption/verification works
        String message = "Public Only Test";
        String encrypted = publicOnly.encrypt(message);
        String signature = myKey.sign(message);
        assertTrue(publicOnly.isSignatureValid(message, signature));

        // Test decryption/signing fails
        assertThrows(IllegalStateException.class, () -> publicOnly.decrypt(encrypted));
        assertThrows(IllegalStateException.class, () -> publicOnly.sign(message));
    }

    @Test
    void testLoadPublicKeyOnly() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        String pubPath = tempDir.resolve("myKey.pub").toString();
        MyKeyPair publicOnly = new MyKeyPair(pubPath);

        assertNotNull(publicOnly.getPublicKey());
        assertNull(publicOnly.getPrivateKey());
        assertEquals(myKey.getPublicKeyId(), publicOnly.getPublicKeyId());

        // Test encryption works
        String message = "Load Public Only Test";
        assertDoesNotThrow(() -> publicOnly.encrypt(message));
    }
}
