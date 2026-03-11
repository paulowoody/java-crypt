# AsymmetricCipher

`AsymmetricCipher` is an interface that defines the core contract for asymmetric cryptography within the `java-crypt` project.

## What is it for?
By defining a generic interface, the application logic (such as secure email and TLS certificates) can be completely decoupled from any specific algorithmic implementation (like RSA). This enables developers to easily substitute newer, faster algorithms (like Elliptic Curve Cryptography / ECC) in the future without breaking existing application code.

Asymmetric cryptography algorithms always require two paired keys:

1. **Public Key:** Shared openly to allow others to encrypt messages for you and verify your digital signatures.
2. **Private Key:** Kept secret to allow you to decrypt messages sent to you and create your digital signatures.

## Core Operations

Any class implementing this interface must provide implementations for:
- `String encrypt(String message)`: Encrypting a plaintext payload into Base64 using the Public Key.
- `String decrypt(String encrypted)`: Decrypting a Base64 ciphertext back to plaintext using the Private Key.
- `String sign(String message)`: Generating a Base64 cryptographic signature of a payload using the Private Key.
- `boolean isSignatureValid(String message, String signature)`: Verifying a Base64 signature against a payload using the Public Key.
- `String getAlgorithm()`: Returning the standard Java algorithm name (e.g., `"RSA"`, `"EC"`).

## Usage Example
```java
// Programming to the interface allows easy swapping of algorithms
AsymmetricCipher cipher = new MyKeyPair(); // Currently implements RSA

String secret = "Sensitive Data";
String encrypted = cipher.encrypt(secret);
String decrypted = cipher.decrypt(encrypted);

String signature = cipher.sign(secret);
boolean isValid = cipher.isSignatureValid(secret, signature);
```
