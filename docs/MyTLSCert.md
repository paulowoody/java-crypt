# MyTLSCert

`MyTLSCert` handles the creation, wrapping, and verification of X.509 TLS Certificates using
standard Java APIs only — no internal JVM classes, no external dependencies.

## What is it for?
A TLS Certificate securely binds a public key to an identity (like a domain name: `localhost`
or `example.com`). This is the foundation of HTTPS. When a client connects to a server, the
server presents its certificate. The client verifies the certificate's digital signature to
ensure it is talking to the correct server.

## How it works

- **Standards-based:** Certificates are constructed by hand-encoding the X.509 ASN.1/DER
  structure using a lightweight internal utility (`DerEncoder`), then signed using the standard
  `java.security.Signature` API, and finally parsed back into an `X509Certificate` via
  `CertificateFactory`. No `sun.security.x509` internal APIs are used.
- **Self-Signed:** The certificate is signed by the exact same private key whose public key it
  contains. This is suitable for development and demonstration; production use requires a
  Certificate Authority.
- **Algorithm-aware:** The signing algorithm and its `AlgorithmIdentifier` parameters are
  derived automatically from the key type — no manual selection needed:

| Key Type (`getAlgorithm()`) | Certificate Signing Algorithm |
|---|---|
| `RSASSA-PSS` | RSASSA-PSS with SHA-256/MGF1/salt=32 (full PSS parameters) |
| `RSA` | SHA-256 with RSA (PKCS#1 v1.5) |
| `EC` | SHA-256 with ECDSA |

## Usage Example

### Generating a Self-Signed Certificate
```java
// 1. Generate a key pair (RSA-PSS by default via MyKeyPair)
AsymmetricCipher serverKeyPair = new MyKeyPair();

// 2. Generate a certificate valid for 365 days
MyTLSCert tlsCert = new MyTLSCert(serverKeyPair, "CN=api.mydomain.com", 365);

// 3. Save it to disk for the web server to use
Helper.saveCert(tlsCert.getCertificate(), "server-cert.pem");
```

### Verifying a Certificate
```java
// Load a certificate that was received or saved previously
X509Certificate downloadedCert = Helper.readCert("server-cert.pem");
MyTLSCert clientView = new MyTLSCert(downloadedCert);

// Verify the certificate's signature against a trusted public key
boolean isValid = clientView.verifySignature(trustedServerPublicKey);
```

## How the certificate is assembled

An X.509 certificate is an ASN.1 structure encoded in DER (Distinguished Encoding Rules).
`MyTLSCert` builds this structure in three steps:

1. **Resolve the algorithm** — selects the correct JCA algorithm name, OID, and parameter
   encoding based on the key type.
2. **Encode `TBSCertificate`** — assembles the to-be-signed portion: version, serial number,
   algorithm identifier, issuer/subject name, validity period, and public key.
3. **Sign and assemble** — signs the `TBSCertificate` bytes with `java.security.Signature`,
   wraps the result in the outer `Certificate` SEQUENCE, and parses it into a standard
   `X509Certificate` via `CertificateFactory`.

## PSS AlgorithmIdentifier Structure

RSASSA-PSS certificates require an explicit `AlgorithmIdentifier` with encoded parameters. This
structure must appear identically in both the `TBSCertificate.signature` field and the outer
`Certificate.signatureAlgorithm` field (RFC 4055 §3.3):

```
AlgorithmIdentifier for RSASSA-PSS ::= SEQUENCE {
  algorithm  OID 1.2.840.113549.1.1.10,   -- id-RSASSA-PSS
  parameters RSASSA-PSS-params ::= SEQUENCE {
    hashAlgorithm    [0] SEQUENCE {
                           OID 2.16.840.1.101.3.4.2.1  -- id-sha256
                         },
    maskGenAlgorithm [1] SEQUENCE {
                           OID 1.2.840.113549.1.1.8,    -- id-mgf1
                           SEQUENCE {
                             OID 2.16.840.1.101.3.4.2.1 -- id-sha256
                           }
                         },
    saltLength       [2] INTEGER 32,
    trailerField     [3] INTEGER 1
  }
}
```

The `PSSParameterSpec` used for `Signature.setParameter()` uses the same values (SHA-256,
MGF1-SHA256, saltLength=32) so the runtime signature matches the encoded parameters exactly.

## Design Notes

**What is fixed:**
- The DER encoding rules (they are a standard).
- The X.509 v3 certificate structure (RFC 5280).
- The PSS parameter values (SHA-256/MGF1-SHA256/salt=32) — these match `MyKeyPair`'s existing
  signature parameters and must not diverge.

**What is extensible without touching the core signing flow:**
- Adding a new key algorithm (e.g., Ed25519): add one entry to the `resolveSigningAlgorithm`
  dispatch table. Ed25519 has no parameters, so `encodedParameters` would be null.
- Changing PSS parameters (e.g., larger salt): update the named constants in `MyTLSCert` —
  the change propagates to both the DER output and the `PSSParameterSpec` automatically.

**What is deliberately not generalised:**
- Certificate extensions (SANs, key usage, etc.) — out of scope. The implementation produces
  a minimal v3 cert with no extensions, consistent with the original.
- Multi-issuer chains — self-signed only.
- Configurable hash algorithms per call — the algorithm is derived from the key type, not
  passed as a parameter, to prevent key/cert algorithm mismatches.

## Standard Java APIs

No external dependencies. No `--add-exports` flags. Runs on any standard JVM from Java 11 onwards.

| API | Package | Since |
|---|---|---|
| `CertificateFactory` | `java.security.cert` | Java 1.2 |
| `Signature` | `java.security` | Java 1.1 |
| `PSSParameterSpec` | `java.security.spec` | Java 1.4 |
| `MGF1ParameterSpec` | `java.security.spec` | Java 1.5 |
| `X500Principal` | `javax.security.auth.x500` | Java 1.4 |
| `SecureRandom`, `BigInteger` | `java.security`, `java.math` | Java 1.1 |
