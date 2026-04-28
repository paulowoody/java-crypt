# DerEncoder

`DerEncoder` is a package-private utility class that encodes Java values into
ASN.1/DER binary format. It is the low-level building block used by `MyTLSCert`
to construct X.509 certificates from scratch without relying on internal JVM APIs.

## What is it for?

X.509 certificates, RSA keys, and many other cryptographic structures are stored and
transmitted as binary data encoded in **DER (Distinguished Encoding Rules)** — a strict
binary serialisation format defined by the ASN.1 standard (ITU-T X.690).

Every value in a DER stream is represented as a **Tag-Length-Value (TLV)** triplet:

| Field | Purpose | Example |
|---|---|---|
| **Tag** | Identifies the data type (1 byte) | `0x02` = INTEGER |
| **Length** | Number of bytes in the value | `0x04` = 4 bytes follow |
| **Value** | The raw content bytes | `0x01 0x00 0x01` = 65537 |

`DerEncoder` encodes the specific subset of ASN.1 types that an X.509 v3 certificate
requires. It has no knowledge of certificates or keys — it is a pure serialisation utility.

## Supported ASN.1 Types

| Method | ASN.1 Type | Tag | Used for |
|---|---|---|---|
| `encodeInteger(BigInteger)` | INTEGER | `0x02` | Serial number, version, PSS salt length |
| `encodeOid(String)` | OBJECT IDENTIFIER | `0x06` | Algorithm identifiers (e.g. SHA-256, RSA-PSS) |
| `encodeBitString(byte[])` | BIT STRING | `0x03` | Signature bytes, SubjectPublicKeyInfo |
| `encodeUtcTime(Date)` | UTCTime | `0x17` | Certificate validity dates |
| `encodeNull()` | NULL | `0x05` | RSA AlgorithmIdentifier parameters field |
| `encodeSequence(byte[]...)` | SEQUENCE | `0x30` | All structured containers in X.509 |
| `encodeExplicitTag(int, byte[])` | `[n] EXPLICIT` | `0xA0+n` | Version field, PSS parameter components |

## How It Works

### Building bottom-up

DER structures are assembled inside-out: encode the innermost values first, then wrap
them in enclosing SEQUENCEs. For example, an `AlgorithmIdentifier` for SHA-256 is built as:

```java
// 1. Encode the OID for SHA-256
byte[] sha256Oid = DerEncoder.encodeOid("2.16.840.1.101.3.4.2.1");

// 2. Wrap it in a SEQUENCE to form an AlgorithmIdentifier
byte[] algId = DerEncoder.encodeSequence(sha256Oid);

// 3. Wrap in an explicit [0] context tag (as used in PSS params)
byte[] tagged = DerEncoder.encodeExplicitTag(0, algId);
```

### Length encoding

Short lengths (0–127) are a single byte. Longer lengths use the multi-byte long form:
the first byte is `0x80 | numBytes`, followed by the length value in big-endian byte order.
This is handled automatically by every encoding method.

### OID encoding

Object Identifiers (OIDs) are encoded in base-128. The first two arc components `X.Y`
are merged into one byte (`40 * X + Y`). Each subsequent arc is encoded in 7-bit groups,
most-significant first, with the high bit set on all but the last byte as a continuation flag.

## Design Principles

- **Stateless:** Every method is a pure function returning a new `byte[]`. No internal state,
  no builder pattern. Any call can be made independently.
- **No coupling:** `DerEncoder` knows nothing about certificates, keys, or algorithms.
  Adding a new DER type means adding a new static method — nothing else changes.
- **Composable:** Since every method returns `byte[]`, results are passed directly into
  `encodeSequence` and `encodeExplicitTag` to build arbitrarily nested structures.

## Scope and Limitations

`DerEncoder` encodes only the types needed for X.509 v3 certificate generation:

- **Not included:** OctetString, UTF8String, PrintableString, IA5String, GeneralizedTime,
  SET, BOOLEAN, or multi-byte tags. These can be added as new static methods if needed.
- **Dates:** Uses `UTCTime` only, valid for years 1950–2049. Certificates expiring after
  2049 would require `GeneralizedTime` (tag `0x18`).
- **Decoding:** `DerEncoder` is encode-only. Parsing DER back into Java objects is handled
  by `CertificateFactory` and the standard `java.security` API.
