# Demo

`Demo` is the main entry point and executable harness for the `java-crypt` project. 

## What is it for?
It acts as a comprehensive, narrative-driven tutorial. By running `Demo.java`, you execute a simulated real-world interaction between two parties ("Alice" and "Bob"), as well as "Eve" (a malicious hacker). It prints detailed logs to the console to visualize how keys are generated, secrets are exchanged, and payloads are manipulated.

## The Scenarios
The demonstration systematically walks through 6 distinct scenarios:

1. **RSA Key Pair Generation:** Alice and Bob independently generate their asymmetric public/private key pairs.
2. **Key Exchange (RSA + AES):** Alice gets Bob's **Public Key** and uses it to encrypt a fast, random AES key. She sends the encrypted package to Bob. Bob uses his **Private Key** to decrypt it.
3. **Secure Messaging & Digital Signatures:** Bob encrypts a secret message with the shared AES key, signs it with his **Private Key**, and sends it back. Alice verifies the signature using Bob's **Public Key** to ensure authenticity.
4. **Real-World JWT Scenario:** Demonstrates an API server generating a stateless JWT, a client successfully using it, and a hacker failing to forge a tampered JWT payload.
5. **Real-World TLS Certificate Scenario:** Alice generates a self-signed X.509 certificate to secure an HTTPS endpoint. Bob downloads and verifies it. Eve attempts to impersonate Alice with a forged certificate, but Bob's verification catches the invalid signature.
6. **Secure Email Scenario:** Alice uses a custom AES/RSA pipeline to sign and encrypt a MimeMultipart email for Bob. The email is saved to the filesystem as an `.eml` file. Eve intercepts it but cannot decrypt it. Eve then attempts to forge an email to Bob claiming to be from Alice, but Bob detects the forgery during signature verification.

## How to run it

Assuming you have packaged the application via Maven (`mvn clean package`), you can execute the demonstration using the fat jar:

```bash
java -jar target/java-crypt-0.1.0-SNAPSHOT-assembly.jar
```
