package net.repro;

import net.perseity.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Focuses on verifying that an external consumer can successfully use
 * the library's primary features (JWT, Encryption, and KeyPairs).
 */
public class CryptoTest {

    @Test
    public void testClientUsageScenario() throws Exception {
        // 1. Client generates keys
        MyKeyPair clientKeys = new MyKeyPair();
        assertNotNull(clientKeys.getPublicKeyId());

        // 2. Client uses TokenProvider (JWT)
        TokenProvider tokenProvider = new MyJwt();
        String secret = "client-shared-secret";
        String token = tokenProvider.createToken("client_user", secret);
        assertTrue(tokenProvider.verifyToken(token, secret));

        // 3. Client uses SymmetricCipher (AES)
        SymmetricCipher cipher = new MyCrypt();
        String message = "Client Secret Message";
        String encrypted = cipher.encrypt(message);
        assertEquals(message, cipher.decrypt(encrypted));
    }
}
