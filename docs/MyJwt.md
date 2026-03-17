# MyJwt (TokenProvider)

`MyJwt` implements the `TokenProvider` interface to handle the creation and verification of JSON Web Tokens (JWTs).

## What is a JWT?
JSON Web Tokens are an open, industry standard (RFC 7519) for representing claims securely between two parties. They are typically used for:
- **Authentication**: After login, the server returns a JWT which the client includes in subsequent API requests.
- **Information Exchange**: Securely transmitting information between parties. Because JWTs can be signed, you can be sure that the senders are who they say they are and that the content hasn't been tampered with.

## The TokenProvider Interface
By implementing an interface, the library is prepared for future expansion. For example, you could add a `MyPaseto` implementation or an `RsaJwtProvider` without changing the application logic that depends on `TokenProvider`.

```java
public interface TokenProvider {
    String createToken(String subject, String secret) throws Exception;
    boolean verifyToken(String token, String secret);
}
```

## Implementation Details
This implementation uses **HMAC SHA-256** (Symmetric) to sign tokens.

- **Header**: Contains the algorithm (`HS256`) and the token type (`JWT`).
- **Payload**: Contains standard claims:
  - `sub`: Subject (the user identity).
  - `iss`: Issuer (`perseity.net`).
  - `exp`: Expiration time (5 minutes).
  - `iat`: Issued-at time.
  - `jti`: Unique Token ID.
- **Signature**: Prevents tampering. It is calculated as `HMACSHA256(Base64URL(Header) + "." + Base64URL(Payload), secret)`.

## Usage Example

```java
TokenProvider tokenProvider = new MyJwt();
String secret = "VerySecretKey123!";

// 1. Create a token for a user
String token = tokenProvider.createToken("alice", secret);

// 2. Verify the token later
boolean isValid = tokenProvider.verifyToken(token, secret);
```
