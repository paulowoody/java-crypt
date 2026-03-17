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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
        org.junit.jupiter.api.Assertions.assertNotNull(signature);
        org.junit.jupiter.api.Assertions.assertTrue(myCrypt.isSignatureValid(message, signature));
    }

    @Test
    void verifyFailsWithWrongMessage() throws Exception {
        String message = "Hello, HMAC!";
        String signature = myCrypt.sign(message);
        org.junit.jupiter.api.Assertions.assertFalse(myCrypt.isSignatureValid(message + " altered", signature));
    }
}