package net.perseity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MySecureEmailTest {

    private MyKeyPair senderKeyPair;
    private MyKeyPair recipientKeyPair;
    private MyKeyPair attackerKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        senderKeyPair = new MyKeyPair();
        recipientKeyPair = new MyKeyPair();
        attackerKeyPair = new MyKeyPair();
    }

    @Test
    void testSignAndEncryptDecryptAndVerify() throws Exception {
        String originalMessage = "This is a highly classified secret message.";

        // Encrypt and Sign
        javax.mail.internet.MimeMultipart secureEmail = MySecureEmail.signAndEncrypt(originalMessage, senderKeyPair, recipientKeyPair);

        // Simulate network transmission
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        secureEmail.writeTo(baos);
        javax.mail.internet.MimeMultipart receivedEmail = new javax.mail.internet.MimeMultipart(new javax.mail.util.ByteArrayDataSource(baos.toByteArray(), "multipart/mixed"));

        // Decrypt and Verify
        MySecureEmail.DecryptedEmail result = MySecureEmail.decryptAndVerify(receivedEmail, recipientKeyPair, senderKeyPair);

        assertEquals(originalMessage, result.getMessage());
        assertTrue(result.isSignatureValid());
    }

    @Test
    void testEveIntercepts() throws Exception {
        String originalMessage = "Secret for Bob";
        javax.mail.internet.MimeMultipart secureEmail = MySecureEmail.signAndEncrypt(originalMessage, senderKeyPair, recipientKeyPair);

        // Eve tries to decrypt with her own key instead of Bob's
        assertThrows(Exception.class, () -> {
            MySecureEmail.decryptAndVerify(secureEmail, attackerKeyPair, senderKeyPair);
        }, "Eve should not be able to decrypt the message encrypted for Bob.");
    }

    @Test
    void testEveForges() throws Exception {
        String forgedMessage = "Transfer the money to me.";
        
        // Eve encrypts it for Bob, but signs it with her own key (claiming to be Alice)
        javax.mail.internet.MimeMultipart secureEmail = MySecureEmail.signAndEncrypt(forgedMessage, attackerKeyPair, recipientKeyPair);

        // Bob receives it and decrypts it, but expects the signature to be from Alice (senderKeyPair)
        MySecureEmail.DecryptedEmail result = MySecureEmail.decryptAndVerify(secureEmail, recipientKeyPair, senderKeyPair);

        assertFalse(result.isSignatureValid(), "The signature should be invalid because it was not signed by Alice.");
    }
}