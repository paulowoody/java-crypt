package net.perseity;

import org.junit.jupiter.api.Test;
import java.io.File;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class MyTLSCertTest {

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
        
        String certPath = "test-cert.pem";
        
        try {
            Helper.saveCert(tlsCert.getCertificate(), certPath);
            File certFile = new File(certPath);
            assertTrue(certFile.exists());
            
            X509Certificate loadedCert = Helper.readCert(certPath);
            assertNotNull(loadedCert);
            assertEquals(tlsCert.getCertificate(), loadedCert);
            
            MyTLSCert loadedTLSCert = new MyTLSCert(loadedCert);
            assertTrue(loadedTLSCert.verifySignature(keyPair.getPublicKey()));
        } finally {
            File fileToDelete = new File(certPath);
            if (fileToDelete.exists() && !fileToDelete.delete()) {
                fileToDelete.deleteOnExit();
            }
        }
    }
}