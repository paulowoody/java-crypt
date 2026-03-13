package net.perseity;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Handles the creation and verification of JSON Web Tokens (JWTs).
 * JWTs are used for securely transmitting information between parties as a JSON object.
 * This implementation uses HMAC SHA-256 (symmetric key) to sign the tokens,
 * meaning both the creator and the verifier must share the same secret key.
 */
public class MyJwt {
    /**
     * Jackson ObjectMapper for JSON serialization and deserialization.
     */
    private static final ObjectMapper mapper = new ObjectMapper();

    /**
     * Private constructor to prevent instantiation of this utility class.
     */
    private MyJwt() {
        // Utility class
    }

    /**
     * Generates a new signed JWT for a given subject (e.g., a username).
     * The token includes standard claims:
     * - sub: The subject of the token.
     * - iss: The issuer (who created the token).
     * - exp: Expiration time (set to 5 minutes from creation).
     * - iat: Issued-at time.
     * - jti: JWT ID (a unique identifier for this specific token).
     *
     * @param subject The identity being authenticated (e.g., user ID).
     * @param secret  The shared secret key used to sign the token via HMAC.
     * @return A Base64-URL encoded JWT string containing three parts: Header.Payload.Signature
     * @throws NoSuchAlgorithmException If the HmacSHA256 algorithm is not available.
     * @throws InvalidKeyException If the secret key is invalid.
     * @throws JsonProcessingException If JSON serialization of the header or payload fails.
     */
    public static String createToken(String subject, String secret) throws NoSuchAlgorithmException, InvalidKeyException, JsonProcessingException {
        Instant now = Instant.now();
        Instant expiry = now.plus(5, ChronoUnit.MINUTES);

        Map<String, Object> header = new HashMap<>();
        header.put("alg", "HS256");
        header.put("typ", "JWT");

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", subject);
        payload.put("iss", "perseity.net");
        payload.put("exp", expiry.getEpochSecond());
        payload.put("iat", now.getEpochSecond());
        payload.put("jti", UUID.randomUUID().toString());

        String headerJson = mapper.writeValueAsString(header);
        String payloadJson = mapper.writeValueAsString(payload);

        String encodedHeader = Helper.b64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8));
        String encodedPayload = Helper.b64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        String message = encodedHeader + "." + encodedPayload;
        String signature = sign(message, secret);

        return message + "." + signature;
    }

    /**
     * Verifies the structure, cryptographic signature, and expiration of a given JWT.
     * 
     * @param token  The three-part JWT string to verify.
     * @param secret The shared secret key expected to have been used to sign the token.
     * @return True if the token is structurally valid, the signature matches, and it is not expired. False otherwise.
     */
    public static boolean verifyToken(String token, String secret) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }

            String message = parts[0] + "." + parts[1];
            String expectedSignature = sign(message, secret);

            // Use MessageDigest.isEqual for constant-time comparison to prevent timing attacks
            byte[] expectedBytes = expectedSignature.getBytes(StandardCharsets.UTF_8);
            byte[] actualBytes = parts[2].getBytes(StandardCharsets.UTF_8);
            if (!MessageDigest.isEqual(expectedBytes, actualBytes)) {
                return false; // Signature doesn't match
            }

            // Verify expiration
            String payloadJson = new String(Helper.b64UrlDecode(parts[1]), StandardCharsets.UTF_8);
            Map<String, Object> payload = mapper.readValue(payloadJson, new TypeReference<Map<String, Object>>() {});
            if (payload.containsKey("exp")) {
                long exp = ((Number) payload.get("exp")).longValue();
                if (Instant.now().getEpochSecond() > exp) {
                    return false; // Token has expired
                }
            }

            return true; // Token is valid and not expired
        } catch (Exception e) {
            // Any parsing errors, malformed Base64, or crypto errors invalidate the token
            return false;
        }
    }

    /**
     * Core cryptographic function that generates an HMAC SHA-256 signature for the token data.
     * The signature ensures the Header and Payload cannot be tampered with by a third party.
     * 
     * @param message The message to sign (usually Header.Payload).
     * @param secret The shared secret key to use for HMAC.
     * @return The HMAC signature as a Base64-URL encoded String.
     * @throws NoSuchAlgorithmException If the HmacSHA256 algorithm is not available.
     * @throws InvalidKeyException If the secret key is invalid.
     */
    private static String sign(String message, String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] hash = secret.getBytes(StandardCharsets.UTF_8);
        Mac sha256Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(hash, "HmacSHA256");
        sha256Hmac.init(secretKey);
        byte[] signedBytes = sha256Hmac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        return Helper.b64UrlEncode(signedBytes);
    }
}
