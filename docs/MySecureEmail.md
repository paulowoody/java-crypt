# MySecureEmail

`MySecureEmail` demonstrates how to create a highly secure, encrypted, and digitally signed email using only standard Java cryptography libraries, avoiding heavy third-party dependencies like BouncyCastle.

## What is it for?
It provides end-to-end email security mimicking the core concepts of S/MIME:
- **Authenticity & Integrity:** Proves exactly who sent the email and that it hasn't been altered.
- **Confidentiality:** Ensures only the intended recipient can read the message.

*Note: While cryptographically sound, this implementation uses custom MIME formatting (`application/x-encrypted-key` and `application/x-encrypted-payload`). True S/MIME compliance requires formatting payloads into CMS (Cryptographic Message Syntax / PKCS#7), which Java cannot natively do without external libraries.*

## How it works
1.  **Signing:** The plaintext message is signed using the Sender's RSA `PrivateKey`.
2.  **Payload Encryption:** A fast, temporary AES Session Key is generated. The signed message is encrypted using this AES key via a `SymmetricCipher` (like `MyCrypt`).
3.  **Key Transport:** The AES Session Key is encrypted using the Recipient's RSA `PublicKey` via an `AsymmetricCipher` (like `MyKeyPair`).
4.  **Packaging:** Both the encrypted AES key and the encrypted payload are packaged into a standard `javax.mail.internet.MimeMultipart`.
5.  **Decryption:** The recipient uses their RSA `PrivateKey` to decrypt the AES key, uses the AES key to decrypt the payload, and uses the sender's RSA `PublicKey` to verify the signature.

## Usage Example

### Sending a Secure Email
```java
String secretMessage = "Classified Project Data";

// Sender signs with their key, encrypts for the recipient
// senderKeyPair and recipientKeyPair should implement AsymmetricCipher
MimeMultipart secureEmail = MySecureEmail.signAndEncrypt(
    secretMessage, 
    senderKeyPair,    // To sign
    recipientKeyPair  // To encrypt
);

// Send the multipart via standard JavaMail transport...
```

### Receiving and Verifying
```java
// Recipient extracts the multipart from the received email
MimeMultipart receivedEmail = (MimeMultipart) message.getContent();

// Decrypt using recipient's private key, verify against sender's public key
MySecureEmail.DecryptedEmail result = MySecureEmail.decryptAndVerify(
    receivedEmail, 
    recipientKeyPair, // To decrypt
    senderKeyPair     // To verify
);

if (result.isSignatureValid()) {
    System.out.println("Secure Message: " + result.getMessage());
} else {
    System.out.println("WARNING: Email signature forged or tampered!");
}
```
