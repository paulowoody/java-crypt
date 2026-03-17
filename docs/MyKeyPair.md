# MyKeyPair

`MyKeyPair` handles asymmetric cryptography using RSA (Rivest–Shamir–Adleman). It implements the `AsymmetricCipher` interface and acts as a wrapper around the standard `java.security.KeyPair`, `Cipher`, and `Signature` classes.

## What is it for?
Asymmetric cryptography utilizes a mathematical pair of keys:

1.  **Public Key:** Safe to share openly. Used by others to **encrypt** data sent to you, or to **verify** digital signatures you've created.
2.  **Private Key:** Must be kept strictly secret. Used by you to **decrypt** data sent to you, or to **create** digital signatures proving your identity.

Because RSA is computationally expensive, it is typically used for exchanging small secrets (like AES session keys) and signing data, rather than encrypting large messages directly.

## How it works
- **Algorithm:** `RSASSA-PSS` for signatures and key generation.
- **Key Size:** Defaults to **2048-bit**.
- **Encryption Padding:** `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` to prevent padding oracle attacks.
- **Signature:** Uses `SHA-256` hashing with `MGF1` mask generation.

## Usage Example

### Generating and Saving Keys
```java
// Generate a new random RSA Key Pair
MyKeyPair keyPair = new MyKeyPair();

// Save the keys to disk in PEM format
Helper.saveKeyPair(keyPair, "public.pem", "private.pem");
```

### Encrypting and Decrypting (Key Exchange)
```java
// Sender encrypts a small secret (like an AES key) using the Recipient's Public Key
String secret = "SuperSecretAESKey123!";
String encryptedSecret = recipientKeyPair.encrypt(secret);

// Recipient decrypts the secret using their Private Key
String decryptedSecret = recipientKeyPair.decrypt(encryptedSecret);
```

### Digital Signatures
```java
// Sender signs a message payload with their Private Key
String payload = "I authorize this transaction.";
String signature = senderKeyPair.sign(payload);

// Recipient verifies the signature using the Sender's Public Key
boolean isValid = senderKeyPair.isSignatureValid(payload, signature);
```
