package net.perseity;

import org.junit.jupiter.api.Test;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class MyJwtTest {

    @Test
    void testCreateAndVerifyToken() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String subject = "user123";

        String token = MyJwt.createToken(subject, secret);
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);

        assertTrue(MyJwt.verifyToken(token, secret));
    }

    @Test
    void testVerifyTokenWithWrongSecret() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String wrongSecret = "wrong-secret-key";
        String subject = "user123";

        String token = MyJwt.createToken(subject, secret);

        assertFalse(MyJwt.verifyToken(token, wrongSecret));
    }

    @Test
    void testVerifyTokenTamperedPayload() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String token = MyJwt.createToken("user123", secret);

        String[] parts = token.split("\\.");
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"admin\"}".getBytes());
        String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

        assertFalse(MyJwt.verifyToken(tamperedToken, secret));
    }

    @Test
    void testVerifyTokenMalformed() {
        String secret = "super-secret-key-for-hmac";
        assertFalse(MyJwt.verifyToken("not.a.valid.token", secret));
        assertFalse(MyJwt.verifyToken("invalid", secret));
    }
}