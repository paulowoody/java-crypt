# TokenProvider

`TokenProvider` is an interface that defines the contract for generating and verifying security tokens (like JWT).

## What is it for?
Security tokens are used for securely transmitting information between parties. By abstracting this into an interface, the library can support multiple token standards (like JWT or PASETO) or different signing algorithms in a pluggable way.

## Core Operations
- `String createToken(String subject, String secret)`: Generates a new signed security token for a given subject using a shared secret.
- `boolean verifyToken(String token, String secret)`: Verifies the structure, cryptographic signature, and validity of a given token.

## Usage Example
```java
// Programming to the interface
TokenProvider tokenProvider = new MyJwt();

// 1. Create a token
String token = tokenProvider.createToken("alice_user", "shared_secret_123");

// 2. Verify the token
boolean isValid = tokenProvider.verifyToken(token, "shared_secret_123");
```
