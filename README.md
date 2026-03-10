# java-crypt

## Simple experiments with RSA, AES, JWT, and TLS Certificates in Java

Demonstrates the use of standard Java cryptographic libraries to generate key pairs, securely exchange secrets, encrypt messages, generate/verify JSON Web Tokens (JWTs), and manage self-signed TLS (X.509) Certificates.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details. 

## Copyright

Copyright (C) 2026, Paul Wood.

## Contact

**Project Maintainer:** paulowoody  
**Email:** paulowoody@users.noreply.github.com  
**Issues:** Please use the GitHub [Issues](https://github.com/paulowoody/java-crypt/issues) page for bug reports or feature requests.

## Demonstration Flow

The main demonstration (`net.perseity.Demo`) performs the following steps to simulate a secure exchange between two parties ("Alice" and "Bob"), followed by real-world API and secure server scenarios:

**Part 1: Key Pair Generation (Asymmetric)**
1. Alice and Bob both generate their own personal RSA key pairs (`alice-key` and `bob-key`).

**Part 2: Secure Key Exchange (Asymmetric + Symmetric)**
2. Alice creates a random, highly secure AES shared secret.
3. Alice encrypts the AES shared secret using Bob's public RSA key (meaning only Bob can decrypt it).
4. Bob receives the package and decrypts it using his private RSA key. Both parties now share the same AES secret.

**Part 3: Secure Messaging & Digital Signatures (Symmetric + Asymmetric)**
5. Bob encrypts a secret message using the new AES shared secret (much faster for data than RSA).
6. Bob signs the encrypted message using his private RSA key to prove it came from him.
7. Alice verifies the signature is valid using Bob's public key.
8. Alice decrypts the encrypted secret message using their shared AES secret.

**Part 4: Real-World JWT Scenario (HMAC)**
9. A Server uses the shared secret as an HMAC key to generate a short-lived JSON Web Token (JWT) for a Client.
10. The Client attaches the JWT to an API request.
11. The Server verifies the token's cryptographic signature and expiration timestamp to grant access.
12. A Hacker attempts to tamper with the token's payload, but the Server detects the invalid signature and rejects it.

**Part 5: Real-World TLS Certificate Scenario (X.509)**
13. A Server (Alice) uses her RSA key pair to generate a self-signed TLS Certificate to secure an HTTPS website.
14. A Client (Bob) connects and downloads the certificate.
15. Bob verifies the digital signature of the certificate using Alice's trusted public key to ensure a secure, un-tampered connection.
16. A Hacker (Eve) generates a forged certificate to impersonate Alice, but Bob detects the invalid signature and rejects the connection.

**Part 6: Secure Email Scenario (Custom Implementation without Third-Party CMS)**
*Note: True S/MIME compliance requires formatting the cryptographic payloads using a complex standard called CMS (Cryptographic Message Syntax, or PKCS#7). The Java Standard Library does not have internal support for generating CMS `EnvelopedData` (Encryption). Therefore, to create a fully S/MIME compliant application that standard email clients can natively read, a third-party library like BouncyCastle is required. This project demonstrates the exact same cryptographic concepts (Authenticity, Integrity, and Confidentiality) using only standard Java RSA/AES.*
17. Alice creates a standard MimeMessage and encrypts/signs it using standard AES and RSA.
18. She encrypts the message payload using AES, and encrypts the AES session key using Bob's public RSA key.
19. Bob receives the encrypted message and decrypts the session key using his Private Key, and uses it to decrypt the body.
20. Bob verifies the signature on the decrypted content against Alice's public key to confirm she sent it and it hasn't been tampered with.
21. A Hacker (Eve) intercepts the encrypted email in transit and attempts to decrypt it, but fails because she does not possess Bob's private key.
22. A Hacker (Eve) attempts to forge an email claiming to be from Alice by signing it with her own key and encrypting it for Bob. Bob decrypts it, but detects the forgery because the signature verification fails against Alice's known public key.

## Core Cryptographic Classes

- `AsymmetricCipher`: An interface defining the contract for public/private key systems (like RSA or ECC). Allows easily swapping algorithms.
- `SymmetricCipher`: An interface defining the contract for shared secret systems (like AES). Allows swapping fast encryption algorithms.
- `MyKeyPair`: Implements `AsymmetricCipher` to handle asymmetric cryptography using RSA. Used for key exchange and digital signatures.
- `MyCrypt`: Implements `SymmetricCipher` to handle symmetric encryption/decryption using AES-GCM. Used for encrypting actual message data securely and fast.
- `MyJwt`: Handles the creation and verification of JSON Web Tokens using HMAC SHA-256 signatures.
- `MyTLSCert`: Handles the creation, signing, and verification of TLS (X.509) Certificates using internal `sun.security.x509` APIs.
  - *Note: Because standard Java lacks a public API for certificate generation, this project intentionally uses internal JVM classes to avoid external dependencies. The `pom.xml` configures compiler arguments and jar manifest entries (`Add-Exports: java.base/sun.security.x509`) to bypass the Java Module System restrictions.*
- `MySecureEmail`: Demonstrates secure email concepts (signing, encrypting, decrypting, verifying) using standard Java cryptography instead of heavy third-party S/MIME libraries.
- `Helper`: Provides common Base64 (Standard and URL-Safe) encoding/decoding and PEM file operations for Keys and Certificates.

## Building and Running

Ensure you have Java 24 and Maven installed.

To compile, run the unit tests, and package the application, run:
```bash
mvn clean package
```

To run the unit tests and automatically generate a JaCoCo code coverage report (found in `target/site/jacoco/index.html`), run:
```bash
mvn clean test
```

To run the demonstration and see the narrative flow, execute the built assembly jar:
```bash
java -jar target/java-crypt-0.1.0-SNAPSHOT-assembly.jar
```

## Future
The project already covers several foundational and practical applications of cryptography. To
expand it with more real-world examples, we could consider the following:


1. Password Hashing & Key Derivation (KDF)
   While SymmetricCipher likely uses keys, demonstrating how to securely derive those keys from user
   passwords using industry standards like Argon2, bcrypt, or PBKDF2 is a critical real-world use
   case.


2. Time-based One-Time Passwords (TOTP)
   Implementing the algorithm behind Google Authenticator (RFC 6238). This combines HMAC with a moving
   factor (time) and is the standard for modern Multi-Factor Authentication (MFA).


3. Key Exchange (Diffie-Hellman / ECDH)
   The project has MyKeyPair, but showing how two parties can establish a shared secret over an
   insecure channel using Elliptic Curve Diffie-Hellman (ECDH) is fundamental to how TLS works under
   the hood.


4. JSON Object Encryption (JWE)
   You already have MyJwt (which is typically signed, i.e., a JWS). Adding JWE would demonstrate how
   to encrypt the payload of a JWT so that sensitive identity information isn't visible to the client
   or intermediaries.

5. Secure File Storage (AES-GCM)
   A utility for encrypting/decrypting local files. This would involve handling initialization vectors
   (IVs), salt management, and authenticated encryption to ensure the file hasn't been tampered with
   while stored.


6. Digital Signatures (Detached & CMS)
   Extending the asymmetric examples to show detached signatures for software updates or CMS
   (Cryptographic Message Syntax) for formal document signing.

## Changes

- 0.1.0-SNAPSHOT
    - 2026-03-10, Added Secure Email functions with pure standard library `MySecureEmail` implementation.
    - 2026-03-10, Added Hacker/Eve interception and forgery scenarios to both the TLS and Secure Email examples.
    - 2026-03-10, Updated `Demo.java` to output secure email payloads as `.eml` files to disk for inspection.
    - 2026-03-09, Added TLS/X.509 self-signed certificate generation using native Java libraries (`sun.security.x509`).
    - 2026-03-09, Added JWT/HMAC support, real-world scenario narrative, extensive Javadocs, and URL-Safe Base64 helpers.
    - 2026-03-09, Update documentation with demonstration flow and build instructions.
    - 2025-06-24, Added RSA/AES functionality.
