# Helper

`Helper` is a static utility class that centralizes file I/O, format conversion, and Base64 encoding across the library.

## What is it for?
Cryptography relies heavily on moving binary byte arrays between different formats and transporting them across networks. `Helper` standardizes:
- **Base64 Encoding/Decoding:** Standard and URL-Safe representations.
- **PEM File Operations:** Writing and reading RSA Keys and X.509 Certificates using standard Privacy-Enhanced Mail (PEM) headers (e.g., `-----BEGIN PUBLIC KEY-----`).
- **Binary Utilities:** Standardizing core cryptographic operations like concatenating byte arrays and converting hashes to human-readable hex strings.
- **JavaMail Configuration:** Ensures the JVM handles specific MIME types correctly.

## Usage Examples

### Binary Utilities
```java
// Concatenate two byte arrays (e.g., IV + Ciphertext)
byte[] combined = Helper.appendByteArray(arrayA, arrayB);

// Convert a hash (e.g., a Key Fingerprint) to a colon-separated hex string
// Output: "A1:B2:C3:D4:..."
String hexString = Helper.bytesToHexString(someHashBytes);
```

### Base64 Encoding
```java
byte[] rawBytes = "Hello".getBytes();

// Standard Base64 (Includes +, /, and padding =)
String standard = Helper.b64Encode(rawBytes); 

// URL-Safe Base64 (Strips padding, replaces + and / for safe URL transmission, like JWTs)
String urlSafe = Helper.b64UrlEncode(rawBytes);
```

### PEM Files (Keys and Certificates)
```java
// Save an AsymmetricCipher (e.g. RSA KeyPair) to disk
Helper.saveKeyPair(myKeyPair, "public.pem", "private.pem");

// Load an existing KeyPair from disk into an AsymmetricCipher implementation
AsymmetricCipher loadedKeys = new MyKeyPair();
Helper.loadKeyPair(loadedKeys, "public.pem", "private.pem");

// Read a Certificate
X509Certificate cert = Helper.readCert("server-cert.pem");
```

### Email I/O
```java
// Setup Mailcap to prevent UnsupportedDataTypeExceptions in fat jars
Helper.setupMailcap();

// Save a MimeMultipart email payload to disk (.eml)
Helper.saveMimeMultipart(multipart, "secure-email.eml");

// Load it back
MimeMultipart loadedEmail = Helper.loadMimeMultipart("secure-email.eml");
```
