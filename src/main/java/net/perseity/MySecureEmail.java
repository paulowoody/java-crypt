package net.perseity;

import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;

/**
 * Demonstrates how to create a secure (signed and encrypted) email using ONLY
 * standard Java cryptography (RSA and AES-GCM). 
 * 
 * Note on S/MIME Compliance: 
 * This class mimics the exact cryptographic concepts of S/MIME (Authenticity, 
 * Integrity, Confidentiality) but is NOT technically S/MIME compliant. 
 * True S/MIME requires wrapping the payloads in a complex standard called 
 * CMS (Cryptographic Message Syntax, or PKCS#7). The standard Java Library 
 * (sun.security) does not have internal classes for generating CMS EnvelopedData 
 * (Encrypted payloads). To create a fully compliant S/MIME email that standard 
 * clients (like Outlook or Apple Mail) can natively read, a heavy third-party 
 * CMS library like BouncyCastle is required.
 */
public class MySecureEmail {

    /**
     * Signs the email body with the sender's private key, and encrypts it with 
     * a temporary AES key which is then encrypted for the recipient.
     *
     * @param messageBody       The plaintext message.
     * @param senderKeyPair     The sender's RSA Key Pair (used to sign).
     * @param recipientKeyPair  The recipient's RSA Key Pair (used to encrypt the session key).
     * @return A MimeBodyPart containing the encrypted key and payload.
     */
    public static MimeMultipart signAndEncrypt(String messageBody, MyKeyPair senderKeyPair, MyKeyPair recipientKeyPair) throws Exception {
        // 1. Sign the message
        String signature = senderKeyPair.sign(messageBody);
        String signedMessagePayload = messageBody + "\n\n---SIGNATURE---\n" + signature;

        // 2. Encrypt the signed message with a new, random AES key (Symmetric)
        MyCrypt sessionCrypt = new MyCrypt();
        String sessionSecret = sessionCrypt.getSecretKey();
        String encryptedPayload = sessionCrypt.encrypt(signedMessagePayload);

        // 3. Encrypt the AES key with the recipient's RSA Public Key (Asymmetric)
        String encryptedSessionSecret = recipientKeyPair.encrypt(sessionSecret);

        // 4. Construct the custom MIME part to hold both pieces
        MimeMultipart multipart = new MimeMultipart();

        MimeBodyPart keyPart = new MimeBodyPart();
        keyPart.setText(encryptedSessionSecret);
        keyPart.setHeader("Content-Type", "application/x-encrypted-key");
        keyPart.setHeader("Content-Description", "Encrypted AES Key");

        MimeBodyPart payloadPart = new MimeBodyPart();
        payloadPart.setText(encryptedPayload);
        payloadPart.setHeader("Content-Type", "application/x-encrypted-payload");
        payloadPart.setHeader("Content-Description", "Encrypted Signed Payload");

        multipart.addBodyPart(keyPart);
        multipart.addBodyPart(payloadPart);

        return multipart;
    }

    /**
     * Decrypts the secure email body and verifies the sender's signature.
     *
     * @param encryptedEmail    The MimeMultipart containing the encrypted data.
     * @param recipientKeyPair  The recipient's RSA Key Pair (used to decrypt the session key).
     * @param senderKeyPair     The sender's RSA Key Pair (used to verify the signature).
     * @return A DecryptedEmail object containing the message and signature status.
     */
    public static DecryptedEmail decryptAndVerify(MimeMultipart encryptedEmail, MyKeyPair recipientKeyPair, MyKeyPair senderKeyPair) throws Exception {
        MimeBodyPart keyPart = (MimeBodyPart) encryptedEmail.getBodyPart(0);
        MimeBodyPart payloadPart = (MimeBodyPart) encryptedEmail.getBodyPart(1);

        String encryptedSessionSecret;
        try (java.io.InputStream is = keyPart.getInputStream()) {
            encryptedSessionSecret = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
        }
        
        String encryptedPayload;
        try (java.io.InputStream is = payloadPart.getInputStream()) {
            encryptedPayload = new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8).trim();
        }

        // 1. Decrypt the AES key using recipient's Private Key
        String sessionSecret = recipientKeyPair.decrypt(encryptedSessionSecret);

        // 2. Decrypt the payload using the AES key
        MyCrypt sessionCrypt = new MyCrypt(sessionSecret);
        String signedMessagePayload = sessionCrypt.decrypt(encryptedPayload);

        // 3. Extract message and signature
        String[] parts = signedMessagePayload.split("\n\n---SIGNATURE---\n");
        if (parts.length != 2) {
            throw new SecurityException("Invalid secure email format.");
        }
        String messageBody = parts[0];
        String signature = parts[1];

        // 4. Verify the signature using sender's Public Key
        boolean isSignatureValid = senderKeyPair.isSignatureValid(messageBody, signature);

        return new DecryptedEmail(messageBody, isSignatureValid);
    }

    /**
     * Simple wrapper to hold the results of decryption.
     */
    public static class DecryptedEmail {
        private final String message;
        private final boolean validSignature;

        public DecryptedEmail(String message, boolean validSignature) {
            this.message = message;
            this.validSignature = validSignature;
        }

        public String getMessage() { return message; }
        public boolean isSignatureValid() { return validSignature; }
    }
}