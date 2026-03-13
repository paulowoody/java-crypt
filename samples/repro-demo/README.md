# repro-demo

This is a reproduction project for the `java-crypt` library, designed to demonstrate its functionality by pulling the artifact from the Cloudsmith repository.

## Prerequisites

- **Java 21** (Required for the library and specific cryptographic features).
- **Maven** (To manage dependencies and build the project).

## Configuration

The `pom.xml` is pre-configured to:
1.  Pull the `java-crypt` library from the [Cloudsmith Repository](https://maven.cloudsmith.io/paulowoody/java-crypt/).
2.  Include necessary dependencies like `log4j2` and `javax.mail`.
3.  Apply mandatory JVM exports (`--add-exports java.base/sun.security.x509=ALL-UNNAMED`). This is required to expose Java's internal cryptographic libraries, allowing for a native crypto implementation (e.g., for TLS certificate generation) while avoiding external dependencies like Bouncy Castle.

## How to Build & Test

From the `repro-demo` directory, run:

```bash
mvn clean package
```

This will:
1.  **Compile** the source code.
2.  **Run Unit Tests** (located in `src/test/java`).
3.  **Generate an Assembly Jar** in the `target/` directory containing all dependencies.

## How to Run

### Option 1: Using Maven Exec (Recommended for development)

To run the reproduction demo:

```bash
mvn exec:exec
```

### Option 2: Using the Assembly Jar

To run the standalone executable jar (requires mandatory export flag):

```bash
java --add-exports java.base/sun.security.x509=ALL-UNNAMED -jar target/repro-demo-1.0-SNAPSHOT-jar-with-dependencies.jar
```

## Running Tests

To run only the unit tests:

```bash
mvn test
```

> **Note:** We use `exec:exec` instead of `exec:java` to ensure that the required JVM `--add-exports` arguments are correctly passed to a new JVM instance.

## Expected Output

The demo will perform the following steps:
1.  **RSA Key Pair Generation:** Creates and saves public/private keys for "Alice" and "Bob".
2.  **Key Exchange:** Alice encrypts an AES shared secret with Bob's public key; Bob decrypts it.
3.  **Secure Messaging:** Bob sends an AES-encrypted and RSA-signed message to Alice; Alice verifies and decrypts it.
4.  **JWT Scenario:** Demonstrates creating and verifying a JWT using the shared secret.
5.  **TLS Certificate Scenario:** Generates a self-signed certificate for Alice and verifies it from Bob's perspective.
6.  **Secure Email Scenario:** Alice sends a signed and encrypted MimeMultipart email to Bob; Bob decrypts and verifies it.

## Troubleshooting

If you encounter an `IllegalAccessError` related to `sun.security.x509`, ensure you are using `mvn exec:exec` or passing the following flag to your `java` command:

```bash
--add-exports java.base/sun.security.x509=ALL-UNNAMED
```
