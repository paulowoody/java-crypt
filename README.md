# java-crypt

## Simple experiments with RSA and AES in Java

Demonstrate the use of RSA and AES to generate and share an encryption key with another agent/user.

### Demonstration Flow

The main demonstration (`net.perseity.Demo`) performs the following steps:
1. Generates sender and recipient RSA key pairs (`myKey` and `yourKey`).
2. Sender creates a shared secret (AES).
3. Sender encrypts the shared secret using the recipient's public key.
4. Recipient decrypts the shared secret using their private key.
5. Recipient encrypts a secret message using the decrypted shared secret.
6. Recipient signs the encrypted message using their private key.
7. Original sender verifies the signature is valid.
8. Original sender decrypts the encrypted secret message using the shared secret.

### Building and Running

Ensure you have Java 24 and Maven installed.

To compile and package the application, run:
```bash
mvn clean package
```

To run the demonstration, execute the built assembly jar:
```bash
java -jar target/java-crypt-0.1.0-SNAPSHOT-assembly.jar
```

## Changes

- 0.1.0-SNAPSHOT
    - 2026-03-09, Update documentation with demonstration flow and build instructions.
    - 2025-06-24, Paul Wood
