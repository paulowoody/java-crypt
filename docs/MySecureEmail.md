# MySecureEmail (SecureMessageTransport)

`MySecureEmail` implements the `SecureMessageTransport` interface to handle the complex flow of signing and encrypting message payloads (specifically emails) using a combination of asymmetric and symmetric cryptography.

## What is it for?
In real-world communication, messages need to be both:
1. **Authenticated**: So the recipient knows who sent the message (Digital Signature).
2. **Confidential**: So only the intended recipient can read it (Asymmetric Encryption).

This class follows the high-level logic used in **S/MIME** (Secure/Multipurpose Internet Mail Extensions).

## The SecureMessageTransport Interface
By abstracting this into an interface, you could easily swap the current "custom" implementation for a fully compliant `SMimeProvider` (which might use a library like BouncyCastle to handle CMS/PKCS#7 formatting) without changing the core demonstration or application code.

```java
public interface SecureMessageTransport {
    MimeMultipart signAndEncrypt(String body, AsymmetricCipher sender, AsymmetricCipher recipient) throws Exception;
    DecryptedEmail decryptAndVerify(MimeMultipart email, AsymmetricCipher recipient, AsymmetricCipher sender) throws Exception;
}
```

## How the Custom Flow Works
Because the standard Java library doesn't include easy-to-use S/MIME formatting, this class demonstrates the *concepts* by building a custom MIME-compliant message:

1. **Sign**: Alice signs the message body using her **Private RSA Key**.
2. **Bundle**: The original message and the signature are bundled into a payload.
3. **Symmetric Encrypt**: A random, one-time **AES Session Key** is generated to encrypt the bundled payload.
4. **Asymmetric Encrypt**: The AES Session Key is encrypted using Bob's **Public RSA Key**.
5. **MIME Construction**: A `MimeMultipart` message is created with two parts:
   - Part 1: The Encrypted AES Session Key.
   - Part 2: The Encrypted Payload.

Bob then reverses this process using his **Private RSA Key** to recover the AES key, and Alice's **Public RSA Key** to verify the signature.

## Usage Example

```java
SecureMessageTransport emailTransport = new MySecureEmail();

// Alice signs and encrypts for Bob
MimeMultipart secureEmail = emailTransport.signAndEncrypt("Secret message!", aliceKeyPair, bobKeyPair);

// Bob decrypts and verifies
SecureMessageTransport.DecryptedEmail result = emailTransport.decryptAndVerify(secureEmail, bobKeyPair, aliceKeyPair);

if (result.isSignatureValid()) {
    System.out.println("Verified message: " + result.getMessage());
}
```
