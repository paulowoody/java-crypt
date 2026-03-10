# java-crypt

## Simple experiments with RSA, AES, JWT, and TLS Certificates in Java

Demonstrates the use of standard Java cryptographic libraries to generate key pairs, securely exchange secrets, encrypt messages, generate/verify JSON Web Tokens (JWTs), and manage self-signed TLS (X.509) Certificates.

### Demonstration Flow

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

### Core Cryptographic Classes

- `MyKeyPair`: Handles asymmetric cryptography (Public/Private Key Pairs) using RSA. Used for key exchange and digital signatures.
- `MyCrypt`: Handles symmetric encryption/decryption using AES-GCM. Used for encrypting actual message data securely and fast.
- `MyJwt`: Handles the creation and verification of JSON Web Tokens using HMAC SHA-256 signatures.
- `MyTLSCert`: Handles the creation, signing, and verification of TLS (X.509) Certificates using internal `sun.security.x509` APIs.
  - *Note: Because standard Java lacks a public API for certificate generation, this project intentionally uses internal JVM classes to avoid external dependencies. The `pom.xml` configures compiler arguments and jar manifest entries (`Add-Exports: java.base/sun.security.x509`) to bypass the Java Module System restrictions.*
- `Helper`: Provides common Base64 (Standard and URL-Safe) encoding/decoding and PEM file operations for Keys and Certificates.

### Building and Running

Ensure you have Java 24 and Maven installed.

To compile, run the unit tests, and package the application, run:
```bash
mvn clean package
```

To run the demonstration and see the narrative flow, execute the built assembly jar:
```bash
java -jar target/java-crypt-0.1.0-SNAPSHOT-assembly.jar
```

## Changes

- 0.1.0-SNAPSHOT
    - 2026-03-09, Added TLS/X.509 self-signed certificate generation using native Java libraries (`sun.security.x509`).
    - 2026-03-09, Added JWT/HMAC support, real-world scenario narrative, extensive Javadocs, and URL-Safe Base64 helpers.
    - 2026-03-09, Update documentation with demonstration flow and build instructions.
    - 2025-06-24, Added RSA/AES functionality.
