package net.perseity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for MySecureEmail class, verifying the full 
 * sign-and-encrypt / decrypt-and-verify flow for secure messaging.
 */
class MySecureEmailTest {

    private MyKeyPair senderKeyPair;
    private MyKeyPair recipientKeyPair;
    private MyKeyPair attackerKeyPair;
    private SecureMessageTransport emailTransport;

    @BeforeEach
    void setUp() throws Exception {
        senderKeyPair = new MyKeyPair();
        recipientKeyPair = new MyKeyPair();
        attackerKeyPair = new MyKeyPair();
        emailTransport = new MySecureEmail();
    }

    @Test
    void testSignAndEncryptDecryptAndVerify() throws Exception {
        String originalMessage = "This is a highly classified secret message.";

        // Encrypt and Sign
        MimeMultipart secureEmail = emailTransport.signAndEncrypt(originalMessage, senderKeyPair, recipientKeyPair);

        // Simulate network transmission
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        secureEmail.writeTo(baos);
        MimeMultipart receivedEmail = new MimeMultipart(new ByteArrayDataSource(baos.toByteArray(), "multipart/mixed"));

        // Decrypt and Verify
        SecureMessageTransport.DecryptedEmail result = emailTransport.decryptAndVerify(receivedEmail, recipientKeyPair, senderKeyPair);

        assertEquals(originalMessage, result.getMessage());
        assertTrue(result.isSignatureValid());
    }

    @Test
    void testEveIntercepts() throws Exception {
        String originalMessage = "Secret for Bob";
        MimeMultipart secureEmail = emailTransport.signAndEncrypt(originalMessage, senderKeyPair, recipientKeyPair);

        // Eve tries to decrypt with her own key instead of Bob's
        assertThrows(Exception.class, () -> {
            emailTransport.decryptAndVerify(secureEmail, attackerKeyPair, senderKeyPair);
        }, "Eve should not be able to decrypt the message encrypted for Bob.");
    }

    @Test
    void testEveForges() throws Exception {
        String forgedMessage = "Transfer the money to me.";
        
        // Eve encrypts it for Bob, but signs it with her own key (claiming to be Alice)
        MimeMultipart secureEmail = emailTransport.signAndEncrypt(forgedMessage, attackerKeyPair, recipientKeyPair);

        // Bob receives it and decrypts it, but expects the signature to be from Alice (senderKeyPair)
        SecureMessageTransport.DecryptedEmail result = emailTransport.decryptAndVerify(secureEmail, recipientKeyPair, senderKeyPair);

        assertFalse(result.isSignatureValid(), "The signature should be invalid because it was not signed by Alice.");
    }

    @Test
    void testMalformedSecureEmail() throws Exception {
        // Create an email with missing delimiter
        SymmetricCipher sessionCrypt = new MyCrypt();
        String encrypted = sessionCrypt.encrypt("No delimiter here");
        String encryptedKey = recipientKeyPair.encrypt(sessionCrypt.getSecretKey());

        MimeMultipart multipart = new MimeMultipart();
        javax.mail.internet.MimeBodyPart keyPart = new javax.mail.internet.MimeBodyPart();
        keyPart.setText(encryptedKey);
        javax.mail.internet.MimeBodyPart payloadPart = new javax.mail.internet.MimeBodyPart();
        payloadPart.setText(encrypted);
        multipart.addBodyPart(keyPart);
        multipart.addBodyPart(payloadPart);

        assertThrows(SecurityException.class, () -> emailTransport.decryptAndVerify(multipart, recipientKeyPair, senderKeyPair));
    }
}
