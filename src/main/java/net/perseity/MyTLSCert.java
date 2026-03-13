package net.perseity;

import sun.security.x509.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Handles the creation and management of TLS (X.509) Certificates.
 * A TLS Certificate securely binds a public key to an identity (like a domain name),
 * which is then digitally signed by a Certificate Authority (or self-signed).
 * This implementation uses the internal sun.security.x509 package to generate
 * self-signed certificates for demonstration purposes using standard Java compatible methods.
 */
public class MyTLSCert {

    /**
     * The underlying X.509 certificate.
     */
    private final X509Certificate certificate;

    /**
     * Creates a new self-signed TLS certificate for the given KeyPair and domain name.
     *
     * @param cipher     The AsymmetricCipher containing the public and private keys.
     * @param domainName The subject name for the certificate (e.g., "CN=localhost").
     * @param daysValid  The number of days the certificate should be valid.
     * @throws Exception If certificate generation or signing fails.
     */
    public MyTLSCert(AsymmetricCipher cipher, String domainName, int daysValid) throws Exception {
        this.certificate = generateSelfSignedCert(cipher.getPrivateKey(), cipher.getPublicKey(), domainName, daysValid, cipher.getAlgorithm());
    }

    /**
     * Initializes the MyTLSCert wrapper with an existing certificate.
     * 
     * @param certificate The X509Certificate to wrap.
     */
    public MyTLSCert(X509Certificate certificate) {
        this.certificate = certificate;
    }

    /**
     * Gets the underlying X509Certificate object.
     * 
     * @return The X509Certificate instance.
     */
    public X509Certificate getCertificate() {
        return certificate;
    }

    /**
     * Helper method to generate a self-signed X.509 Certificate.
     * 
     * @param privateKey The private key to sign the certificate with.
     * @param publicKey The public key to include in the certificate.
     * @param domainName The subject/issuer name (e.g., "CN=localhost").
     * @param daysValid Validity period in days.
     * @param keyAlgorithm The algorithm of the keys (e.g., "RSA").
     * @return A newly generated and signed X509Certificate.
     * @throws CertificateException If certificate creation fails.
     * @throws IOException If encoding fails.
     * @throws NoSuchAlgorithmException If the signing algorithm is not available.
     * @throws InvalidKeyException If the private key is invalid.
     * @throws NoSuchProviderException If the security provider is not found.
     * @throws SignatureException If signing fails.
     */
    private X509Certificate generateSelfSignedCert(PrivateKey privateKey, PublicKey publicKey, String domainName, int daysValid, String keyAlgorithm)
            throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {

        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + daysValid * 86400000L); // days to ms
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(domainName);

        info.setValidity(interval);
        info.setSerialNumber(new CertificateSerialNumber(sn));
        info.setSubject(owner);
        info.setIssuer(owner);
        info.setKey(new CertificateX509Key(publicKey));
        info.setVersion(new CertificateVersion(CertificateVersion.V3));
        
        // Choose signing algorithm based on the key algorithm
        String sigAlgo = keyAlgorithm.equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
        if (keyAlgorithm.equals(MyKeyPair.ALGORITHM)) {
            sigAlgo = "SHA256withRSAandMGF1"; // Attempt to use PSS if RSASSA-PSS, or fallback
            // Actually, standard Java X509CertImpl signing might require explicit PSS parameters.
            // For simplicity, we can default to SHA256withRSA since it's just the signing algo of the cert.
            sigAlgo = "SHA256withRSA"; 
        }
        
        AlgorithmId algo = AlgorithmId.get(sigAlgo);
        info.setAlgorithmId(new CertificateAlgorithmId(algo));

        // Sign the cert
        return X509CertImpl.newSigned(info, privateKey, sigAlgo);
    }

    /**
     * Verifies that the certificate was signed using the corresponding private key
     * of the provided public key.
     *
     * @param publicKey The public key of the authority that allegedly signed the certificate.
     * @return true if the signature is valid; false otherwise.
     */
    public boolean verifySignature(PublicKey publicKey) {
        try {
            certificate.verify(publicKey);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
