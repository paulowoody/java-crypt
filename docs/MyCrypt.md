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
- **Password-Based Key Derivation:** Uses `PBKDF2WithHmacSHA256` with 65,535 iterations to derive a strong cryptographic key from a human-readable password and a 16-byte random salt.
- **Signature Algorithm:** `HmacSHA256`. Uses the same shared secret key to create and verify message authentication codes (MACs).

## Core Operations
- `byte[] generateSalt()`: Generates a random 16-byte salt for key derivation.
- `byte[] generateKeyFromPassword(String password)`: Derives a key from a password using a new random salt (returned).
- `void generateKeyFromPassword(String password, byte[] salt)`: Derives a key using an existing salt (for re-derivation).
- `void setSecretKey(String b64Key)`: Manually sets the active secret key from a Base64 string.

## Usage Example

### Password-Based Encryption
```java
MyCrypt crypt = new MyCrypt();

// 1. Derive a key from a user's password
String password = "User-Specific-Password-123!";
byte[] salt = crypt.generateKeyFromPassword(password);

// 2. Encrypt data
String ciphertext = crypt.encrypt("Secret data protected by password.");

// 3. To decrypt later, you need the SAME password and the SAME salt
MyCrypt decryptor = new MyCrypt();
decryptor.generateKeyFromPassword(password, salt);
String original = decryptor.decrypt(ciphertext);
```

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
