# MyJwt

`MyJwt` is a lightweight utility for creating and verifying JSON Web Tokens (JWTs) using standard Java cryptography and `com.fasterxml.jackson.databind.ObjectMapper`.

## What is it for?
JWTs are an industry standard (RFC 7519) used primarily for API authentication and authorization. A JWT is a URL-safe, base64-encoded string containing a JSON payload. 
The token is cryptographically signed by the server so that the server can trust the data inside it without needing to look it up in a database on every request.

## How it works
- **Algorithm:** `HMAC SHA-256` (HS256). This is a symmetric signing algorithm, meaning the server uses the same secret key to both sign the token and verify it later.
- **Payload:** Automatically injects standard claims such as `sub` (Subject/User ID), `iss` (Issuer), `iat` (Issued At), `exp` (Expiration Time), and `jti` (JWT ID).
- **Security:** If a malicious user intercepts the token and alters the payload (e.g., changing the `sub` to "admin"), the cryptographic verification will fail because the signature will no longer match the payload.

## Usage Example

### Creating a Token
```java
String serverSecret = "super_secret_server_key_12345";
String userId = "user_89891";

// Creates a token valid for 24 hours
String jwt = MyJwt.createToken(userId, serverSecret);
System.out.println("Bearer " + jwt);
```

### Verifying a Token
```java
// When the user makes an API request, verify the attached token
boolean isAuthorized = MyJwt.verifyToken(jwt, serverSecret);

if (isAuthorized) {
    // Grant access
} else {
    // Return 401 Unauthorized (Token is expired, tampered with, or invalid)
}
```
