# MyTLSCert

`MyTLSCert` handles the creation, wrapping, and verification of X.509 TLS Certificates using standard Java.

## What is it for?
A TLS Certificate securely binds a public key to an identity (like a domain name: `localhost` or `example.com`). This is the foundation of HTTPS. 
When a client connects to a server, the server presents its certificate. The client verifies the certificate's digital signature to ensure they are talking to the real server and not an imposter.

## How it works
- **Internal APIs:** Because the standard Java public API lacks a direct way to generate X.509 certificates from scratch, this class utilizes the internal `sun.security.x509` package. 
- **Self-Signed:** It generates self-signed certificates, meaning the certificate is signed by the exact same private key that it contains.
- **Algorithm:** Uses `SHA256withRSA` for signing the certificate.

*Note: To compile and run applications using this class, your project must expose the internal module via `--add-exports=java.base/sun.security.x509=ALL-UNNAMED`.*

## Usage Example

### Generating a Self-Signed Certificate
```java
// 1. Generate an RSA Key Pair for the server
MyKeyPair serverKeyPair = new MyKeyPair();

// 2. Generate a Certificate valid for 365 days for a specific domain
MyTLSCert tlsCert = new MyTLSCert(serverKeyPair, "CN=api.mydomain.com", 365);

// 3. Save it to disk for the web server to use
Helper.saveCert(tlsCert.getCertificate(), "server-cert.pem");
```

### Verifying a Certificate
```java
// Client connects and downloads the certificate
X509Certificate downloadedCert = Helper.readCert("server-cert.pem");
MyTLSCert clientView = new MyTLSCert(downloadedCert);

// Client verifies the certificate against a Public Key they already trust
boolean isValid = clientView.verifySignature(trustedServerPublicKey);
```
