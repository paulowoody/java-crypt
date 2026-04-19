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
- **Signature:** Uses `RSASSA-PSS` to sign the **SHA-256 hash** of the message, with `MGF1` mask generation.
- **Key Fingerprints:** `getPublicKeyId()` and `getPrivateKeyId()` generate unique 8-byte hexadecimal identifiers based on the key's mathematical components.

## Public-Key-Only Instances
A key feature of asymmetric cryptography is the ability to share your **Public Key** with others while keeping your **Private Key** secret. `MyKeyPair` supports "Public-Only" instances for this purpose.

- **`getPublicOnly()`:** Creates a new `MyKeyPair` instance containing *only* the public key. This is the safe way to share your key with another party.
- **`new MyKeyPair(publicKeyFile)`:** Loads only the public key from a PEM file.
- **`new MyKeyPair(publicKey)`:** Creates an instance from an existing `java.security.PublicKey`.

Operations that require a private key (`sign` and `decrypt`) will throw an `IllegalStateException` if called on a Public-Only instance.

## Usage Example

### Generating and Saving Keys
```java
// Generate a new random RSA Key Pair
MyKeyPair keyPair = new MyKeyPair();

// Log unique identifiers for the keys
System.out.println("Public ID: " + keyPair.getPublicKeyId());
System.out.println("Private ID: " + keyPair.getPrivateKeyId());

// Save the keys to disk in PEM format
Helper.saveKeyPair(keyPair, "public.pem", "private.pem");
```

// Safely share your public key with Alice
MyKeyPair publicOnlyForAlice = keyPair.getPublicOnly();
```

### Encrypting and Decrypting (Key Exchange)
```java
// Alice loads Bob's Public Key from disk
MyKeyPair bobsPublicKey = new MyKeyPair("bob-public.pem");

// Alice encrypts a small secret (like an AES key) using Bob's Public Key
String secret = "SuperSecretAESKey123!";
String encryptedSecret = bobsPublicKey.encrypt(secret);

// Bob decrypts the secret using his full KeyPair (including Private Key)
String decryptedSecret = bobsKeyPair.decrypt(encryptedSecret);
```

### Digital Signatures
```java
// Bob signs a message payload with his Private Key
String payload = "I authorize this transaction.";
String signature = bobsKeyPair.sign(payload);

// Alice verifies the signature using Bob's Public Key
MyKeyPair bobsPublicKey = new MyKeyPair("bob-public.pem");
boolean isValid = bobsPublicKey.isSignatureValid(payload, signature);
```
