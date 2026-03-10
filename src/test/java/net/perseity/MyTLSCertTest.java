package net.perseity;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.nio.file.Path;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class MyTLSCertTest {

    @TempDir
    Path tempDir;

    @Test
    void testCreateAndVerifyTLSCert() throws Exception {
        MyKeyPair keyPair = new MyKeyPair();
        String domain = "CN=test.perseity.net";
        
        MyTLSCert tlsCert = new MyTLSCert(keyPair, domain, 365);
        X509Certificate cert = tlsCert.getCertificate();
        
        assertNotNull(cert);
        assertEquals(domain, cert.getSubjectX500Principal().getName());
        
        // Verify signature with its own public key (self-signed)
        assertTrue(tlsCert.verifySignature(keyPair.getPublicKey()));
    }
    
    @Test
    void testVerifySignatureFailsWithWrongKey() throws Exception {
        MyKeyPair keyPair1 = new MyKeyPair();
        MyKeyPair keyPair2 = new MyKeyPair();
        
        MyTLSCert tlsCert = new MyTLSCert(keyPair1, "CN=test.perseity.net", 365);
        
        // Verifying with a different public key should fail
        assertFalse(tlsCert.verifySignature(keyPair2.getPublicKey()));
    }
    
    @Test
    void testSaveAndLoadCert() throws Exception {
        MyKeyPair keyPair = new MyKeyPair();
        MyTLSCert tlsCert = new MyTLSCert(keyPair, "CN=localhost", 30);
        
        Path certPath = tempDir.resolve("test-cert.pem");
        String certFileString = certPath.toString();
        
        Helper.saveCert(tlsCert.getCertificate(), certFileString);
        File certFile = certPath.toFile();
        assertTrue(certFile.exists());
        
        X509Certificate loadedCert = Helper.readCert(certFileString);
        assertNotNull(loadedCert);
        assertEquals(tlsCert.getCertificate(), loadedCert);
        
        MyTLSCert loadedTLSCert = new MyTLSCert(loadedCert);
        assertTrue(loadedTLSCert.verifySignature(keyPair.getPublicKey()));
    }
}
