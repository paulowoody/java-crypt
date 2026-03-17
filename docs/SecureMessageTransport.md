# SecureMessageTransport

`SecureMessageTransport` is an interface that defines a high-level contract for secure message transport, handling complex flows like signing and encrypting messages.

## What is it for?
In secure communications, it's often necessary to ensure both **authenticity** (the message is from who it says it is) and **confidentiality** (only the intended recipient can read it). `SecureMessageTransport` provides a high-level API to perform these operations in a single flow.

By using an interface, the library can be extended to support standard protocols like **S/MIME** (Secure/Multipurpose Internet Mail Extensions) using third-party libraries without changing the consumer code.

## Core Operations
- `MimeMultipart signAndEncrypt(String messageBody, AsymmetricCipher sender, AsymmetricCipher recipient)`: Signs a message with the sender's private key and encrypts it for the recipient's public key.
- `DecryptedEmail decryptAndVerify(MimeMultipart encryptedEmail, AsymmetricCipher recipient, AsymmetricCipher sender)`: Decrypts the message using the recipient's private key and verifies the signature using the sender's public key.

## DecryptedEmail (Result Object)
The `decryptAndVerify` method returns a `DecryptedEmail` object with the following methods:
- `String getMessage()`: Returns the decrypted plaintext message.
- `boolean isSignatureValid()`: Returns true if the digital signature was validly verified.

## Usage Example
```java
// Programming to the interface
SecureMessageTransport transport = new MySecureEmail();

// 1. Alice signs and encrypts for Bob
MimeMultipart secureEmail = transport.signAndEncrypt("Secret message!", aliceKeyPair, bobKeyPair);

// 2. Bob decrypts and verifies
SecureMessageTransport.DecryptedEmail result = transport.decryptAndVerify(secureEmail, bobKeyPair, aliceKeyPair);

if (result.isSignatureValid()) {
    String originalMessage = result.getMessage();
}
```
