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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MyCryptTest {
    private static final Logger logger = LogManager.getLogger(MyCryptTest.class);

    private static MyCrypt myCrypt;

    @BeforeAll
    public void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException {
        myCrypt = new MyCrypt();
    }

    @AfterAll
    public void tearDown() {
        logger.info("Finished.");
    }

    @Test
    void constructorDoesNotThrowError() {
        assertDoesNotThrow(() -> new MyCrypt());
    }

    @Test
    void setKeyFromPassword() {
        String password = "Test";
        assertDoesNotThrow(() -> myCrypt.generateKeyFromPassword(password));
    }

    @Test
    void setAndGetSecretKey() {
        String expected = "VGVzdA==";
        myCrypt.setSecretKey(expected);
        String key = myCrypt.getSecretKey();
        assertEquals(expected, key);
    }

    @Test
    void encrypt() {
        String message = "Test";
        assertDoesNotThrow(() -> myCrypt.encrypt(message));
    }

    @Test
    void decrypt() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String expected = "Test";
        String secret = "V2eqscX5FQunCq5exEJX+bV83dlt8gHnpT8VnVsEUJo=";
        String encrypted = "KyYD6Wqkf2K4sXU0X0pV6CRvhmUTs10JtmRDfMeBsgQ=";
        assertDoesNotThrow(() -> myCrypt.setSecretKey(secret));
        assertDoesNotThrow(() -> myCrypt.decrypt(encrypted));
        assertEquals(expected, myCrypt.decrypt(encrypted));
    }

    @Test
    void signAndVerify() throws Exception {
        String message = "Hello, HMAC!";
        String signature = myCrypt.sign(message);
        assertNotNull(signature);
        assertTrue(myCrypt.isSignatureValid(message, signature));
    }

    @Test
    void verifyFailsWithWrongMessage() throws Exception {
        String message = "Hello, HMAC!";
        String signature = myCrypt.sign(message);
        assertFalse(myCrypt.isSignatureValid(message + " altered", signature));
    }

    @Test
    void testDecryptTooShort() {
        assertThrows(IllegalArgumentException.class, () -> myCrypt.decrypt(Helper.b64Encode(new byte[11])));
    }

    @Test
    void testKeyFromPasswordAndSalt() throws Exception {
        String password = "StrongPassword123";
        byte[] salt = myCrypt.generateSalt();
        
        myCrypt.generateKeyFromPassword(password, salt);
        String key1 = myCrypt.getSecretKey();
        
        myCrypt.generateKeyFromPassword(password, salt);
        String key2 = myCrypt.getSecretKey();
        
        assertEquals(key1, key2);
    }
}
