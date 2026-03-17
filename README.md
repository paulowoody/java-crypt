# java-crypt

## Simple experiments with RSA, AES, JWT, and TLS Certificates in Java

Demonstrates the use of standard Java cryptographic libraries to generate key pairs, securely exchange secrets, encrypt messages, generate/verify JSON Web Tokens (JWTs), and manage self-signed TLS (X.509) Certificates.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details. 

## Copyright

Copyright © 2026, Paul Wood.

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
3. Alice encrypts the AES shared secret using **Bob's Public Key only**. By using a Public-Only instance, she ensures her own private key remains separate and safe.
4. Bob receives the package and decrypts it using his Private RSA key. Both parties now share the same AES secret.

**Part 3: Secure Messaging & Digital Signatures (Symmetric + Asymmetric)**

5. Bob encrypts a secret message using the new AES shared secret (much faster for data than RSA).
6. Bob signs the encrypted message using his Private RSA key to prove it came from him.
7. Alice verifies the signature is valid using **Bob's Public Key only**.
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

## Maven Usage

The `java-crypt` library is deployed to a public Cloudsmith repository. To use it in your own Maven project, add the following to your `pom.xml`:

### Repository Configuration

```xml
<repositories>
  <repository>
    <id>paulowoody-java-crypt</id>
    <url>https://dl.cloudsmith.io/public/paulowoody/java-crypt/maven/</url>
    <releases>
      <enabled>true</enabled>
      <updatePolicy>always</updatePolicy>
    </releases>
    <snapshots>
      <enabled>true</enabled>
      <updatePolicy>always</updatePolicy>
    </snapshots>
  </repository>
</repositories>
```

### Dependency Coordinates

```xml
<dependency>
  <groupId>net.perseity</groupId>
  <artifactId>java-crypt</artifactId>
  <version>0.1.0-SNAPSHOT</version>
</dependency>
```

## Building and Running

Ensure you have Java 21 and Maven 3 installed.

### Compiler Configuration
This project uses internal JVM APIs (`sun.security.x509`) for certificate generation to avoid external dependencies. As a result, the `pom.xml` is configured with:
- `-source 21` and `-target 21` instead of `--release 21`, as the latter strictly enforces public API boundaries and would block access to internal classes.
- `-Xlint:-options` to suppress the compiler warning about not setting the system module location when using `-source`.
- `--add-exports` to allow the compiler and runtime to access the necessary internal packages.

To compile, run the unit tests, and package the application, run:
```bash
mvn clean install
```

*Note: The `clean` goal is configured to also remove temporary cryptographic keys, certificates, and email files (`.pem`, `.key`, `.eml`, etc.) generated in the project root during demonstration runs.*

To run the demonstration and see the narrative flow, you can either execute the built assembly JAR:
```bash
java -jar target/java-crypt-0.1.0-SNAPSHOT-assembly.jar
```
Or use the Maven exec plugin directly (this will compile the code first if needed):
```bash
mvn compile exec:exec
```

To run the unit tests and automatically generate a JaCoCo code coverage report (found in `target/site/jacoco/index.html`), run:
```bash
mvn clean test
```

## Samples

In addition to the main library, this repository includes sample projects that demonstrate how to integrate `java-crypt` into your own applications.

### Repro Demo
Located in `samples/repro-demo`, this project shows how to:
- Configure a Maven project to depend on the `java-crypt` library.
- Access the Cloudsmith Maven repository.
- Correctly set up the JVM export flags (`--add-exports`) required for certificate generation.
- Implement a full cryptographic flow using the library.

To build and run the sample:
```bash
cd samples/repro-demo
mvn clean verify
# Option 1: Run via Maven
mvn compile exec:exec
# Option 2: Run via standalone JAR
java -jar target/repro-demo-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Security and Dependency Management

This project uses `dependencyManagement` in the `pom.xml` to explicitly override versions of transitive dependencies that have known security vulnerabilities. 

For example, we explicitly manage versions of `plexus-archiver` and `plexus-utils` to mitigate Path Traversal and Zip‑Slip vulnerabilities (e.g., [CVE‑2023‑37460](https://nvd.nist.gov/vuln/detail/CVE-2023-37460)) found in transitive dependencies from older Maven plugins.

## Optional: SBOM Generation (CycloneDX)

This project automatically generates a CycloneDX Software Bill of Materials (SBOM) during the Maven build.
The SBOM provides a complete, machine‑readable list of the libraries used by the application, which is useful for supply‑chain security, auditing, and vulnerability scanning.

The SBOM is produced during the package phase and written to:

- `target/bom.json` (JSON format)

- `target/bom.xml` (XML format)

To generate the SBOM manually, run:

`mvn clean package`

After the build completes, you can inspect the SBOM files directly or feed them into external tools such as Grype, Dependency-Track, or other SBOM consumers.

CycloneDX specification and tooling details are available at:

https://cyclonedx.org/

## Optional: Vulnerability Scanning with OWASP Dependency-Check

This project is configured with the [OWASP Dependency-Check Maven Plugin](https://jeremylong.github.io/DependencyCheck/) to identify project dependencies and check for known, publicly disclosed vulnerabilities.

### Running the Scan

The scan is bound to the `verify` phase. Because it requires an NVD API key, it is optional and must be invoked with the key:

```bash
mvn verify -Dnvd.api.key=YOUR_NVD_API_KEY
```

**N.B.** A key may be obtained from: [Request an API Key](https://nvd.nist.gov/developers/request-an-api-key)

The plugin is configured to:
- **Fail the build** if any vulnerabilities with a CVSS score of **7.0 or higher** are found.
- Generate reports in both **HTML** and **JSON** formats in the `target/` directory (e.g., `target/dependency-check-report.html`).

### Storing the API Key in `settings.xml`

To avoid passing the API key on the command line every time, you can add it to your global Maven configuration in `~/.m2/settings.xml`.

e.g. Add the following inside the `<profiles>` section of your `settings.xml` file:

```xml
<profiles>
  <profile>
    <id>owasp-scanning</id>
    <activation>
      <activeByDefault>true</activeByDefault>
    </activation>
    <properties>
      <nvd.api.key>YOUR_NVD_API_KEY_HERE</nvd.api.key>
    </properties>
  </profile>
</profiles>

<activeProfiles>
  <activeProfile>nvd-security</activeProfile>
</activeProfiles>
```

With this configuration, you can run the scan simply by calling:

```bash
mvn verify
```

## Security

This project prioritises cryptographic best practices while remaining a educational resource. Recent updates (March 2026) have addressed several key security areas:
- **Entropy**: Transitioned to modern `SecureRandom` defaults for high-quality entropy.
- **Key Strength**: Upgraded default RSA key sizes to 2048-bit.
- **Robustness**: Fixed issues in password-based key derivation (PBKDF2) and added validation for malformed ciphertexts.
- **Consistency**: Enforced UTF-8 charset across all cryptographic operations to ensure cross-platform compatibility.

For a detailed technical breakdown of these fixes, see [docs/SecurityUpdates.md](docs/SecurityUpdates.md).

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
    - 2026-03-17, **Public Key Separation**:
        - Added explicit support for "Public-Key-Only" instances in `MyKeyPair`.
        - Added `getPublicOnly()` method to safely strip private keys before sharing.
        - Added constructors and `Helper` methods to load only the public key from PEM files.
        - Updated `Demo` and documentation to follow standard public-key infrastructure patterns.
    - 2026-03-16, **Security & Robustness Improvements**:
        - Fixed PBKDF2 salt handling to allow consistent key re-derivation.
        - Transitioned to modern `SecureRandom` (replaced legacy `SHA1PRNG`).
        - Increased default RSA key size from 1024-bit to 2048-bit.
        - Improved robustness of symmetric decryption and signature extraction.
        - Enforced UTF-8 charset consistency across all cryptographic operations.
        - Added detailed documentation in [docs/SecurityUpdates.md](docs/SecurityUpdates.md).
    - 2026-03-16, Added OWASP Dependency‑Check for vulnerability scanning, security overrides for transitive dependencies, and enhanced Maven build with Javadoc and Source plugins.
    - 2026-03-13, Reorganized sample code into `samples/repro-demo` and aligned project structure.
    - 2026-03-10, Refactored to use ephemeral cryptographic keys in tests and support for Java 21+
    - 2026-03-10, Added Secure Email functions with pure standard library `MySecureEmail` implementation.
    - 2026-03-10, Added Hacker/Eve interception and forgery scenarios to both the TLS and Secure Email examples.
    - 2026-03-10, Updated `Demo.java` to output secure email payloads as `.eml` files to disk for inspection.
    - 2026-03-09, Added TLS/X.509 self-signed certificate generation using native Java libraries (`sun.security.x509`).
    - 2026-03-09, Added JWT/HMAC support, real-world scenario narrative, extensive Javadocs, and URL-Safe Base64 helpers.
    - 2026-03-09, Update documentation with demonstration flow and build instructions.
    - 2025-06-24, Added RSA/AES functionality.
