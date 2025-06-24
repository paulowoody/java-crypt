package net.perseity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
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

    @BeforeAll
    public void setup() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Path resourcesPath = Paths.get("src", "test", "resources");
        String resources = resourcesPath.toFile().getAbsolutePath();
        myKey = new MyKeyPair(resources + "/myKey.pub", resources + "/myKey.key");
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
        String encrypted = "qANE9Vd9xVA60NoO426p1f3/mhGwmLPFIOAMs17HJdn+pXezJZf70UG+vCRnj/wP/FsDQp/RCPt+9YuwJQ4eXxfPwIO9adorxg7mrsBrmsT3TC7Cb0BlAXPU67eZ3uTH4ZVpfXdSHpy78Qt17Fd8KYgZCnIk/6Xv1EpfzIe0xp0=";
        String decrypted = myKey.decrypt(encrypted);
        assertEquals(expected, decrypted);
    }

    @Test
    void getEncrypted() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String message = "Hello, World";
        String encrypted = myKey.encrypt(message);
        assertEquals(172, encrypted.length());
    }

    @Test
    void isSignatureValid() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String message = "Hello, World";
        String signature = "LPRWBkJQY7dnQZA9Q3oVjy1w0jXzv8b4IXyKtyvM5hrvOdTbYp5A0ngVpwMnX5LU0hJ2bbnu9nkDyseK3Ygy0xTfZffBZAoRWaOi/nr4uAIPKmW8O5qfUiqSwWP8MW4of28hVAIIkn/hrM9b8DwHF/ufWWWXk7kHJPncWoW7hFQ=";
        assertTrue(myKey.isSignatureValid(message, signature));
    }

    @Test
    void getSigned() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String signature = myKey.sign("Hello, World");
        assertEquals(172, signature.length());
    }

    @Test
    void getPrivateKey() {
        assertEquals(167617570, myKey.getPrivateKey().hashCode());
    }

    @Test
    void getPublicKey() {
        assertEquals(1529754321, myKey.getPublicKey().hashCode());
    }

    @Test
    void getPublicKeyId() throws NoSuchAlgorithmException {
        assertEquals("4E:BF:24:DC:9F:24:8D:29", myKey.getPublicKeyId());
    }

    @Test
    void getPrivateKeyId() throws NoSuchAlgorithmException {
        assertEquals("21:B9:7E:44:DB:4B:04:37", myKey.getPrivateKeyId());
    }
}