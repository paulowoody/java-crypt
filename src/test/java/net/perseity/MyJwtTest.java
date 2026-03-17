package net.perseity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MyJwt class, verifying JWT creation, 
 * signature verification, tampering detection, and expiration handling.
 */
class MyJwtTest {

    private TokenProvider tokenProvider;

    @BeforeEach
    void setUp() {
        tokenProvider = new MyJwt();
    }

    @Test
    void testCreateAndVerifyToken() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String subject = "user123";

        String token = tokenProvider.createToken(subject, secret);
        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);

        assertTrue(tokenProvider.verifyToken(token, secret));
    }

    @Test
    void testVerifyTokenWithWrongSecret() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String wrongSecret = "wrong-secret-key";
        String subject = "user123";

        String token = tokenProvider.createToken(subject, secret);

        assertFalse(tokenProvider.verifyToken(token, wrongSecret));
    }

    @Test
    void testVerifyTokenTamperedPayload() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String token = tokenProvider.createToken("user123", secret);

        String[] parts = token.split("\\.");
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"admin\"}".getBytes());
        String tamperedToken = parts[0] + "." + tamperedPayload + "." + parts[2];

        assertFalse(tokenProvider.verifyToken(tamperedToken, secret));
    }

    @Test
    void testVerifyTokenMalformed() {
        String secret = "super-secret-key-for-hmac";
        assertFalse(tokenProvider.verifyToken("not.a.valid.token", secret));
        assertFalse(tokenProvider.verifyToken("invalid", secret));
    }

    @Test
    void testVerifyTokenExpired() throws Exception {
        String secret = "super-secret-key-for-hmac";
        // Manual JWT with expired 'exp'
        String header = Helper.b64UrlEncode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Helper.b64UrlEncode("{\"sub\":\"user123\",\"exp\":1516239022}".getBytes()); // Expired in 2018
        
        // We need the signature
        String message = header + "." + payload;
        
        // Access private sign method via tokenProvider if possible or just use secret with HmacSHA256 manually
        // Since MyJwt.sign is private, and we are in same package (net.perseity), we might be able to access it if it was package-private.
        // It is private. Let's just use createToken and then tamper with exp if we can.
        // Or just use the same logic.
        
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256"));
        String signature = Helper.b64UrlEncode(mac.doFinal(message.getBytes()));
        
        String expiredToken = message + "." + signature;
        assertFalse(tokenProvider.verifyToken(expiredToken, secret));
    }

    @Test
    void testVerifyTokenNoExp() throws Exception {
        String secret = "super-secret-key-for-hmac";
        String header = Helper.b64UrlEncode("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Helper.b64UrlEncode("{\"sub\":\"user123\"}".getBytes()); // No exp
        String message = header + "." + payload;
        
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256"));
        String signature = Helper.b64UrlEncode(mac.doFinal(message.getBytes()));
        
        String noExpToken = message + "." + signature;
        assertTrue(tokenProvider.verifyToken(noExpToken, secret));
    }
}
