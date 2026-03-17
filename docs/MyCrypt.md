# MyCrypt

`MyCrypt` implements the `SymmetricCipher` interface to handle symmetric encryption and decryption using the **AES** (Advanced Encryption Standard) algorithm in **GCM** (Galois/Counter Mode).

## What is it for?
Symmetric cryptography uses the **exact same key** to both encrypt and decrypt data. 
- It is significantly faster than asymmetric cryptography (RSA).
- It is ideal for encrypting large amounts of data (like message bodies, files, or database columns).
- Because both parties need the same key, it is usually combined with RSA to securely exchange the AES key first.

## How it works
- **Encryption Algorithm:** `AES/GCM/NoPadding`. GCM is an authenticated encryption mode, meaning it not only encrypts the data but also ensures it hasn't been tampered with.
- **Key Size:** 256-bit AES keys.
- **Initialization Vector (IV):** Generates a random 12-byte IV for every encryption operation to ensure identical plaintexts produce completely different ciphertexts. The IV is safely prepended to the final ciphertext so the decryptor can read it.
- **Signature Algorithm:** `HmacSHA256`. Uses the same shared secret key to create and verify message authentication codes (MACs).

## Usage Example

### Symmetric Digital Signatures (HMAC)
```java
// Alice signs a message with the shared secret
String signature = crypt.sign(plaintext);

// Bob verifies the signature using the same shared secret
boolean isValid = decryptor.isSignatureValid(plaintext, signature);
```

### Basic Encryption & Decryption
```java
// Initialize a new MyCrypt instance (automatically generates a new random 256-bit key)
MyCrypt crypt = new MyCrypt();

// Retrieve the base64 encoded key if you need to share it (e.g., via RSA)
String sharedSecretKey = crypt.getSecretKey();

// Encrypt a message
String plaintext = "This is a highly sensitive message.";
String ciphertext = crypt.encrypt(plaintext);

// Later, or on another machine with the same key...
MyCrypt decryptor = new MyCrypt(sharedSecretKey);
String decryptedMessage = decryptor.decrypt(ciphertext);
```
