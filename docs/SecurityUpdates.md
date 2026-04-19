# Security Updates (April 2026)

This document outlines the security improvements and bug fixes implemented in April 2026 to ensure the library follows modern cryptographic best practices.

## 1. Hashing Before Signing
**Issue**: The `sign` and `isSignatureValid` methods in `MyCrypt` (HMAC) and `MyKeyPair` (RSASSA-PSS) were directly processing the message bytes. While functional, it is a best practice to sign a fixed-length cryptographic hash of the message rather than the variable-length message itself, especially for very large payloads.
**Fix**: 
- **Centralized Hashing**: Added a `Helper.hash(String message)` method that computes a SHA-256 digest.
- **Improved Signing**: Updated all `sign` and `isSignatureValid` implementations in `MyCrypt` and `MyKeyPair` to hash the message first using SHA-256. This ensures consistent performance and adheres to stronger cryptographic patterns.
- **Updated Interfaces**: Refined the `SymmetricCipher` and `AsymmetricCipher` Javadocs and documentation to reflect this architectural change.

# Security Updates (March 2026)

This document outlines the security improvements and bug fixes implemented in March 2026 to ensure the library follows modern cryptographic best practices and handles edge cases robustly.

## 1. Password-Based Key Derivation (PBKDF2) Fix
**Issue**: The `MyCrypt.generateKeyFromPassword` method was generating a random salt internally but neither storing nor returning it. This made it impossible for a user to re-derive the same key later (e.g., after an application restart) even with the correct password.
**Fix**: 
- Refactored `generateKeyFromPassword(String password)` to return the randomly generated `byte[] salt`.
- Added an overloaded `generateKeyFromPassword(String password, byte[] salt)` method to allow users to provide a previously generated salt for consistent key re-derivation.

## 2. Transition to Modern SecureRandom
**Issue**: Several classes were explicitly requesting the `SHA1PRNG` algorithm for `SecureRandom`. While widely used in the past, `SHA1PRNG` is now considered legacy, and explicit selection can sometimes lead to platform-specific limitations or weakened entropy if not handled carefully by the provider.
**Fix**: Replaced `SecureRandom.getInstance("SHA1PRNG")` with `new SecureRandom()`. This allows the JVM to use the strongest available default provider for the platform (e.g., `DRBG` on modern OpenJDK), ensuring higher quality entropy.

## 3. RSA Key Strength Upgrade
**Issue**: The default RSA key size in `MyKeyPair` was set to 1024 bits. 1024-bit RSA is no longer considered secure against well-funded attackers and has been deprecated by NIST for several years.
**Fix**: Increased the default RSA key size to **2048 bits**, which is the current industry standard for minimum acceptable security.

## 4. Robust Symmetric Decryption
**Issue**: `MyCrypt.decrypt` was susceptible to an `ArrayIndexOutOfBoundsException` or `IllegalArgumentException` if provided with malformed or truncated ciphertext (shorter than the 12-byte IV).
**Fix**: Added explicit length validation at the start of the `decrypt` method. It now throws a clear `IllegalArgumentException` if the input is too short, preventing low-level runtime crashes.

## 5. Improved Signature Extraction in Secure Email
**Issue**: `MySecureEmail.decryptAndVerify` relied on a simple string split (`.split("\n\n---SIGNATURE---\n")`) to separate the message body from the digital signature. If the message body happened to contain the delimiter string, extraction would fail or become corrupted.
**Fix**: Updated the logic to use `lastIndexOf(delimiter)`. This ensures that even if the delimiter appears within the message text, the actual signature (which is always appended at the very end) is correctly isolated.

## 6. Charset Consistency
**Issue**: `MyKeyPair.isSignatureValid` was using the platform's default charset when converting the message String to bytes. This could lead to signature verification failures if the code was run on different systems with different default encodings (e.g., UTF-8 vs. Windows-1252).
**Fix**: Explicitly specified `StandardCharsets.UTF_8` for all String-to-byte conversions, ensuring consistent behavior across all platforms.

## 7. Improved Separation of Concerns and Symmetric Signing
**Issue**: Common cryptographic utilities (like byte array concatenation and hex string conversion) were duplicated across several classes. Additionally, while the library supported asymmetric signatures (RSA), it lacked a standard way to perform symmetric signing (HMAC), which is often more efficient for message authentication.
**Fix**:
- **Centralized Utilities**: Moved `appendByteArray` and `bytesToHexString` to the `Helper` class. This reduces code duplication and ensures a single, well-tested implementation for these core binary operations.
- **Symmetric Signing (HMAC-SHA256)**: Added `sign` and `isSignatureValid` methods to the `SymmetricCipher` interface and implemented them in `MyCrypt` using **HMAC-SHA256**. This provides a consistent API for both symmetric and asymmetric message authentication.
- **Refined Encryption**: Updated `MyCrypt.encrypt` to use the centralized `Helper.appendByteArray` utility for prepending Initialization Vectors (IVs) to ciphertexts, improving code readability and maintainability.

