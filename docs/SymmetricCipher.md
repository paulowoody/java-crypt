# SymmetricCipher

`SymmetricCipher` is an interface that defines the core contract for symmetric encryption within the `java-crypt` project.

## What is it for?
Symmetric cryptography utilizes the exact same key (a "Shared Secret") to both encrypt and decrypt data. By extracting these operations into a standard interface, consumers of the library can swap out the underlying encryption mechanics (e.g., moving from AES-GCM to ChaCha20-Poly1305) without altering their application logic.

Symmetric algorithms are highly efficient and are the standard choice for encrypting large amounts of data, whereas asymmetric algorithms (like RSA) are used for securely exchanging the symmetric key.

## Core Operations

Any class implementing this interface must provide:
- `String getSecretKey()`: Returning the active shared secret encoded as a Base64 string for easy transport.
- `String encrypt(String plaintext)`: Encrypting a standard string into a Base64-encoded ciphertext.
- `String decrypt(String ciphertext)`: Decrypting a Base64-encoded ciphertext back to its original plaintext.

## Usage Example
```java
// Programming to the interface
SymmetricCipher sessionCrypt = new MyCrypt(); // Currently implements AES-GCM

// Share this key securely with the other party (e.g., via AsymmetricCipher)
String sharedSecretKey = sessionCrypt.getSecretKey();

String ciphertext = sessionCrypt.encrypt("Large classified document payload.");

// The recipient initializes their own cipher using the shared secret
SymmetricCipher recipientCrypt = new MyCrypt(sharedSecretKey);
String originalMessage = recipientCrypt.decrypt(ciphertext);
```
