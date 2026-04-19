# SymmetricCipher

`SymmetricCipher` is an interface that defines the core contract for symmetric encryption within the `java-crypt` project.

## What is it for?
Symmetric cryptography utilizes the **exact same key** (a "Shared Secret") to both encrypt and decrypt data. 
- **The Shared Secret:** This single key must be securely held by both parties. It serves as the foundation for both encryption (privacy) and signing (authenticity).
- **Interchangeability:** By extracting these operations into a standard interface, consumers of the library can swap out the underlying encryption mechanics (e.g., moving from AES-GCM to ChaCha20-Poly1305) without altering their application logic.
- **Efficiency:** Symmetric algorithms are highly efficient and are the standard choice for encrypting large amounts of data, whereas asymmetric algorithms (like RSA) are used for securely exchanging the symmetric key.

## Core Operations

Any class implementing this interface must provide:
- `String getSecretKey()`: Returning the active shared secret encoded as a Base64 string for easy transport.
- `String encrypt(String plaintext)`: Encrypting a standard string into a Base64-encoded ciphertext.
- `String decrypt(String ciphertext)`: Decrypting a Base64-encoded ciphertext back to its original plaintext.
- `String sign(String message)`: Creating a Base64 digital signature of the message's SHA-256 hash using the shared secret (**HMAC**).
- `boolean isSignatureValid(String message, String signature)`: Verifying a Base64 digital signature of the message's SHA-256 hash using the shared secret (**HMAC**).

## Usage Example
```java
// Programming to the interface
SymmetricCipher sessionCrypt = new MyCrypt(); // Currently implements AES-GCM

// Share this key securely with the other party (e.g., via AsymmetricCipher)
String sharedSecretKey = sessionCrypt.getSecretKey();

String ciphertext = sessionCrypt.encrypt("Large classified document payload.");

// Use the shared secret to sign the ciphertext (Authenticated Messaging)
String hmacSignature = sessionCrypt.sign(ciphertext);

// The recipient initializes their own cipher using the shared secret
SymmetricCipher recipientCrypt = new MyCrypt(sharedSecretKey);

// 1. Verify integrity and authenticity first
if (recipientCrypt.isSignatureValid(ciphertext, hmacSignature)) {
    // 2. Decrypt if the signature is valid
    String originalMessage = recipientCrypt.decrypt(ciphertext);
}
```
