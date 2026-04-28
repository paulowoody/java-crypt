package net.perseity;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Date;

/**
 * Handles the creation and management of TLS (X.509) Certificates.
 *
 * <p>A TLS Certificate securely binds a public key to an identity (such as a domain name),
 * which is then digitally signed to prove authenticity. This is the foundation of HTTPS:
 * when a client connects to a server, the server presents its certificate, and the client
 * verifies the signature to confirm it is talking to the correct party.
 *
 * <p>This implementation generates self-signed X.509 v3 certificates — certificates where
 * the same private key that is embedded in the certificate is also used to sign it — using
 * only standard {@code java.security.*} APIs and a hand-rolled ASN.1/DER encoder
 * ({@link DerEncoder}). No internal JVM APIs ({@code sun.security.x509}) are used.
 *
 * <p><b>Supported key algorithms:</b>
 * <ul>
 *   <li>{@code RSASSA-PSS} — signed with full RSASSA-PSS parameters (SHA-256/MGF1/salt=32)</li>
 *   <li>{@code RSA} — signed with SHA-256 with RSA (PKCS#1 v1.5)</li>
 *   <li>{@code EC} — signed with SHA-256 with ECDSA</li>
 * </ul>
 *
 * <p><b>How certificate generation works (overview):</b>
 * <ol>
 *   <li><b>Resolve</b> the signing algorithm and its DER-encoded parameters from the key type.</li>
 *   <li><b>Encode</b> the {@code TBSCertificate} (to-be-signed) structure using {@link DerEncoder}.</li>
 *   <li><b>Sign</b> the TBS bytes with {@link Signature}, then assemble and parse the final cert.</li>
 * </ol>
 */
public class MyTLSCert {

    // -------------------------------------------------------------------------
    // Algorithm OIDs (dot notation — see IANA OID registry and RFCs)
    // -------------------------------------------------------------------------

    /**
     * OID for id-RSASSA-PSS (RFC 4055 §3.1): {@code 1.2.840.113549.1.1.10}
     */
    private static final String OID_RSASSA_PSS = "1.2.840.113549.1.1.10";

    /**
     * OID for sha256WithRSAEncryption (RFC 4055 §5): {@code 1.2.840.113549.1.1.11}
     */
    private static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

    /**
     * OID for ecdsa-with-SHA256 (RFC 5480 §2.1): {@code 1.2.840.10045.4.3.2}
     */
    private static final String OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

    /**
     * OID for id-sha256 (NIST SHA-2): {@code 2.16.840.1.101.3.4.2.1}
     */
    private static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";

    /**
     * OID for id-mgf1 (RFC 4055 §3.1): {@code 1.2.840.113549.1.1.8}
     */
    private static final String OID_MGF1 = "1.2.840.113549.1.1.8";

    // -------------------------------------------------------------------------
    // PSS signing constants — must be consistent between DER encoding and
    // the PSSParameterSpec passed to Signature.setParameter().
    // Changing any of these constants propagates correctly to both.
    // -------------------------------------------------------------------------

    /**
     * Hash algorithm name for PSS (must correspond to {@link #OID_SHA256}).
     */
    private static final String PSS_HASH = "SHA-256";

    /**
     * Mask generation function name for PSS.
     */
    private static final String PSS_MGF = "MGF1";

    /**
     * PSS salt length in bytes. 32 bytes (256 bits) matches the SHA-256 output length.
     */
    private static final int PSS_SALT_LENGTH = 32;

    /**
     * PSS trailer field. The value {@code 1} (the byte {@code 0xBC}) is the only value
     * defined by PKCS#1 and is the universal default.
     */
    private static final int PSS_TRAILER_FIELD = 1;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /**
     * The underlying X.509 certificate held by this instance.
     */
    private final X509Certificate certificate;

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Creates a new self-signed TLS certificate for the given key pair and domain name.
     *
     * @param cipher     The {@link AsymmetricCipher} supplying the public and private keys
     *                   and the algorithm name used to select the signing algorithm.
     * @param domainName The subject/issuer Distinguished Name, e.g. {@code "CN=localhost"}.
     * @param daysValid  Validity period in days from the moment of creation.
     * @throws Exception If certificate generation or signing fails.
     */
    public MyTLSCert(AsymmetricCipher cipher, String domainName, int daysValid) throws Exception {
        this.certificate = generateSelfSignedCert(cipher.getPrivateKey(), cipher.getPublicKey(), domainName, daysValid, cipher.getAlgorithm());
    }

    /**
     * Wraps an existing {@link X509Certificate} for use with {@link #verifySignature}.
     *
     * @param certificate The X.509 certificate to wrap.
     */
    public MyTLSCert(X509Certificate certificate) {
        this.certificate = certificate;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Returns the underlying {@link X509Certificate}.
     *
     * @return The X.509 certificate held by this instance.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Verifies that this certificate's signature was produced by the private key
     * corresponding to the given public key.
     *
     * <p>For a self-signed certificate, pass the same public key that was used to generate
     * the certificate. For a CA-signed certificate, pass the CA's public key.
     *
     * @param publicKey The public key of the authority that signed this certificate.
     * @return {@code true} if the signature is cryptographically valid; {@code false} otherwise.
     */
    public boolean verifySignature(PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // -------------------------------------------------------------------------
    // Certificate generation — three-phase implementation
    // -------------------------------------------------------------------------

    /**
     * Generates a self-signed X.509 v3 certificate in three phases.
     *
     * <h4>Phase 1 — Resolve signing algorithm</h4>
     * <p>{@link #resolveSigningAlgorithm} maps the key algorithm name to a {@link SigningSpec}
     * that bundles the JCA algorithm name, the OID, the DER-encoded algorithm parameters,
     * and (for PSS) the {@link PSSParameterSpec} for {@link Signature#setParameter}.
     *
     * <h4>Phase 2 — DER-encode TBSCertificate</h4>
     * <p>The to-be-signed portion of the certificate is assembled using {@link DerEncoder}.
     * Two fields — the issuer/subject Name and the SubjectPublicKeyInfo — are taken directly
     * from {@link X500Principal#getEncoded()} and {@link PublicKey#getEncoded()} respectively,
     * since those methods already return valid DER encodings.
     *
     * <h4>Phase 3 — Sign and assemble</h4>
     * <p>The TBS bytes are signed with a configured {@link Signature} instance. The outer
     * {@code Certificate} SEQUENCE is then assembled and parsed back into a Java
     * {@link X509Certificate} via {@link CertificateFactory}.
     *
     * @param privateKey   The private key used to sign the certificate.
     * @param publicKey    The public key embedded in the certificate.
     * @param domainName   The subject/issuer DN, e.g. {@code "CN=localhost"}.
     * @param daysValid    Validity period in days.
     * @param keyAlgorithm The key algorithm name from {@link AsymmetricCipher#getAlgorithm()}.
     * @return A newly generated, fully signed {@link X509Certificate}.
     * @throws Exception If any encoding, signing, or parsing step fails.
     */
    private X509Certificate generateSelfSignedCert(PrivateKey privateKey, PublicKey publicKey, String domainName, int daysValid, String keyAlgorithm) throws Exception {

        // ── Phase 1: resolve the signing algorithm spec ──────────────────────
        SigningSpec spec = resolveSigningAlgorithm(keyAlgorithm);
        byte[] algorithmIdentifier = encodeAlgorithmIdentifier(spec);

        // ── Phase 2: DER-encode the TBSCertificate structure ─────────────────
        BigInteger serial = new BigInteger(64, new SecureRandom());
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + (long) daysValid * 86_400_000L);

        // X500Principal.getEncoded() returns a DER-encoded Name — embed directly
        byte[] subjectDer = new X500Principal(domainName).getEncoded();

        // PublicKey.getEncoded() returns DER-encoded SubjectPublicKeyInfo — embed directly
        byte[] spkiDer = publicKey.getEncoded();

        byte[] tbsCertificate = DerEncoder.encodeSequence(
                // version [0] EXPLICIT INTEGER 2 — 0 = v1, 1 = v2, 2 = v3
                DerEncoder.encodeExplicitTag(0, DerEncoder.encodeInteger(BigInteger.TWO)), DerEncoder.encodeInteger(serial), algorithmIdentifier,    // signature algorithm (must be identical in outer Certificate)
                subjectDer,             // issuer — same as subject for self-signed certificates
                DerEncoder.encodeSequence(DerEncoder.encodeUtcTime(notBefore), DerEncoder.encodeUtcTime(notAfter)), subjectDer,             // subject
                spkiDer                 // subjectPublicKeyInfo
        );

        // ── Phase 3: sign TBS bytes and assemble the final Certificate ────────
        Signature signer = Signature.getInstance(spec.jcaAlgorithmName());
        if (spec.pssParameterSpec() != null) {
            // PSS requires explicit parameters; without this call the JVM cannot
            // determine the hash algorithm and salt length to use.
            signer.setParameter(spec.pssParameterSpec());
        }
        signer.initSign(privateKey);
        signer.update(tbsCertificate);
        byte[] signatureBytes = signer.sign();

        // Outer Certificate ::= SEQUENCE { TBSCertificate, AlgorithmIdentifier, BIT STRING }
        // The AlgorithmIdentifier here must be byte-for-byte identical to the one inside TBS.
        byte[] certDer = DerEncoder.encodeSequence(tbsCertificate, algorithmIdentifier, DerEncoder.encodeBitString(signatureBytes));

        // Parse the raw DER bytes into a standard Java X509Certificate
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certDer));
    }

    // -------------------------------------------------------------------------
    // Algorithm dispatch
    // -------------------------------------------------------------------------

    /**
     * Maps a key algorithm name to a {@link SigningSpec} describing how to sign a
     * certificate using that key type and how to encode its {@code AlgorithmIdentifier}.
     *
     * <p>This is the <b>single point of extension</b> for new key algorithm support.
     * To add a new algorithm, add one entry to this switch expression. The three-phase
     * signing flow in {@link #generateSelfSignedCert} requires no modification.
     *
     * @param keyAlgorithm The algorithm name from {@link AsymmetricCipher#getAlgorithm()},
     *                     e.g. {@code "RSASSA-PSS"}, {@code "RSA"}, or {@code "EC"}.
     * @return The resolved {@link SigningSpec} for the given algorithm.
     * @throws IllegalArgumentException If {@code keyAlgorithm} is not a recognised algorithm.
     */
    private SigningSpec resolveSigningAlgorithm(String keyAlgorithm) {
        return switch (keyAlgorithm) {
            case "RSASSA-PSS" -> {
                // PSS requires explicit DER-encoded parameters in the AlgorithmIdentifier
                // AND a PSSParameterSpec passed to Signature.setParameter() before signing.
                PSSParameterSpec pssSpec = new PSSParameterSpec(PSS_HASH, PSS_MGF, MGF1ParameterSpec.SHA256, PSS_SALT_LENGTH, PSS_TRAILER_FIELD);
                yield new SigningSpec("RSASSA-PSS", OID_RSASSA_PSS, encodePssParameters(), pssSpec);
            }
            // RSA uses a NULL parameters field (required by RFC 4055 §5)
            case "RSA" -> new SigningSpec("SHA256withRSA", OID_SHA256_WITH_RSA, DerEncoder.encodeNull(), null);
            // ECDSA has no parameters field — the field is absent, not NULL (RFC 5480 §2.1)
            case "EC" -> new SigningSpec("SHA256withECDSA", OID_ECDSA_WITH_SHA256, null, null);
            default ->
                    throw new IllegalArgumentException("Unsupported key algorithm for certificate signing: " + keyAlgorithm);
        };
    }

    /**
     * Encodes an X.509 {@code AlgorithmIdentifier} SEQUENCE for the given {@link SigningSpec}.
     *
     * <p>The structure and presence of the parameters field depends on the algorithm:
     * <ul>
     *   <li><b>RSA:</b> {@code SEQUENCE { OID, NULL }} — NULL is required, not optional</li>
     *   <li><b>ECDSA:</b> {@code SEQUENCE { OID }} — parameters field is absent</li>
     *   <li><b>RSASSA-PSS:</b> {@code SEQUENCE { OID, RSASSA-PSS-params }} — explicit params</li>
     * </ul>
     *
     * @param spec The {@link SigningSpec} returned by {@link #resolveSigningAlgorithm}.
     * @return DER-encoded {@code AlgorithmIdentifier} bytes.
     */
    private byte[] encodeAlgorithmIdentifier(SigningSpec spec) {
        byte[] oid = DerEncoder.encodeOid(spec.algorithmOid());
        if (spec.encodedParameters() == null) {
            // Parameters field is absent (e.g. ECDSA per RFC 5480)
            return DerEncoder.encodeSequence(oid);
        }
        return DerEncoder.encodeSequence(oid, spec.encodedParameters());
    }

    /**
     * DER-encodes the {@code RSASSA-PSS-params} SEQUENCE as defined in RFC 4055 §3.1.
     *
     * <p>The structure encodes four components, each wrapped in an EXPLICIT context tag
     * so the parser can distinguish them even though all have different types:
     * <pre>
     * RSASSA-PSS-params ::= SEQUENCE {
     *   hashAlgorithm      [0] AlgorithmIdentifier  -- SHA-256
     *   maskGenAlgorithm   [1] AlgorithmIdentifier  -- MGF1 with SHA-256
     *   saltLength         [2] INTEGER              -- 32
     *   trailerField       [3] INTEGER              -- 1 (0xBC)
     * }
     * </pre>
     *
     * <p>The values here are driven by the {@code PSS_*} constants, which are also used
     * to construct the {@link PSSParameterSpec} in {@link #resolveSigningAlgorithm}.
     * Keeping both in sync via shared constants ensures the DER encoding and the
     * actual signing operation use identical parameters.
     *
     * @return DER-encoded {@code RSASSA-PSS-params} SEQUENCE bytes.
     */
    private byte[] encodePssParameters() {
        // The SHA-256 AlgorithmIdentifier appears in two places: hashAlgorithm and
        // inside maskGenAlgorithm. Encode once and reuse.
        byte[] sha256AlgId = DerEncoder.encodeSequence(DerEncoder.encodeOid(OID_SHA256));

        // [0] hashAlgorithm — the hash used before signing
        byte[] hashAlgorithm = DerEncoder.encodeExplicitTag(0, sha256AlgId);

        // [1] maskGenAlgorithm — MGF1 with SHA-256 as its inner hash
        byte[] maskGenAlgorithm = DerEncoder.encodeExplicitTag(1, DerEncoder.encodeSequence(DerEncoder.encodeOid(OID_MGF1), sha256AlgId               // MGF1's own hash AlgorithmIdentifier
        ));

        // [2] saltLength — number of random salt bytes prepended before hashing
        byte[] saltLength = DerEncoder.encodeExplicitTag(2, DerEncoder.encodeInteger(BigInteger.valueOf(PSS_SALT_LENGTH)));

        // [3] trailerField — always 1 (the byte 0xBC) per PKCS#1
        byte[] trailerField = DerEncoder.encodeExplicitTag(3, DerEncoder.encodeInteger(BigInteger.valueOf(PSS_TRAILER_FIELD)));

        return DerEncoder.encodeSequence(hashAlgorithm, maskGenAlgorithm, saltLength, trailerField);
    }

    // -------------------------------------------------------------------------
    // Supporting record
    // -------------------------------------------------------------------------

    /**
     * Captures everything needed to sign a certificate with a specific key algorithm
     * and to DER-encode its {@code AlgorithmIdentifier} field.
     *
     * <p>Each instance corresponds to one entry in the {@link #resolveSigningAlgorithm}
     * dispatch table. Adding support for a new key type means adding one new
     * {@link SigningSpec} there — no other code needs to change.
     *
     * @param jcaAlgorithmName  The JCA algorithm name for {@link Signature#getInstance},
     *                          e.g. {@code "RSASSA-PSS"} or {@code "SHA256withRSA"}.
     * @param algorithmOid      Dot-notation OID for the certificate's AlgorithmIdentifier.
     * @param encodedParameters Pre-encoded DER parameters bytes to include in the
     *                          AlgorithmIdentifier, or {@code null} if the parameters
     *                          field is absent (e.g. ECDSA).
     * @param pssParameterSpec  PSS parameters for {@link Signature#setParameter}, or
     *                          {@code null} for non-PSS algorithms.
     */
    private record SigningSpec(String jcaAlgorithmName, String algorithmOid, byte[] encodedParameters,
                               PSSParameterSpec pssParameterSpec) {
    }
}
