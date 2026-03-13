package net.repro;

import net.perseity.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CryptoTest {

    @Test
    public void testKeyPairGenerationAndEncryption() throws Exception {
        MyKeyPair aliceKeyPair = new MyKeyPair();
        MyKeyPair bobKeyPair = new MyKeyPair();

        String secret = "test-secret";
        String encrypted = bobKeyPair.encrypt(secret);
        String decrypted = bobKeyPair.decrypt(encrypted);

        assertEquals(secret, decrypted);
    }

    @Test
    public void testSignature() throws Exception {
        MyKeyPair bobKeyPair = new MyKeyPair();
        String message = "This is a secret message";
        String signature = bobKeyPair.sign(message);

        assertTrue(bobKeyPair.isSignatureValid(message, signature));
    }

    @Test
    public void testSymmetricEncryption() throws Exception {
        MyCrypt crypt = new MyCrypt();
        String message = "Hello World";
        String encrypted = crypt.encrypt(message);
        String decrypted = crypt.decrypt(encrypted);

        assertEquals(message, decrypted);
    }

    @Test
    public void testJwt() throws Exception {
        String secret = "my-shared-secret";
        String user = "alice_user";
        String token = MyJwt.createToken(user, secret);
        
        assertTrue(MyJwt.verifyToken(token, secret));
    }
}
