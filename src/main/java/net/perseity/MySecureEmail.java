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
     * Private constructor to prevent instantiation of this utility class.
     */
    private MySecureEmail() {
        // Utility class
    }

    /**
     * Signs the email body with the sender's private key, and encrypts it with 
     * a temporary AES key which is then encrypted for the recipient.
     *
     * @param messageBody       The plaintext message.
     * @param senderKeyPair     The sender's RSA Key Pair (used to sign).
     * @param recipientKeyPair  The recipient's RSA Key Pair (used to encrypt the session key).
     * @return A MimeMultipart containing the encrypted session key and the encrypted payload.
     * @throws Exception If signing, encryption, or MIME part creation fails.
     */
    public static MimeMultipart signAndEncrypt(String messageBody, AsymmetricCipher senderKeyPair, AsymmetricCipher recipientKeyPair) throws Exception {
        // 1. Sign the message
        String signature = senderKeyPair.sign(messageBody);
        String signedMessagePayload = messageBody + "\n\n---SIGNATURE---\n" + signature;

        // 2. Encrypt the signed message with a new, random AES key (Symmetric)
        SymmetricCipher sessionCrypt = new MyCrypt();
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
     * @return A DecryptedEmail object containing the decrypted message and its signature verification status.
     * @throws Exception If decryption, signature verification, or MIME parsing fails.
     */
    public static DecryptedEmail decryptAndVerify(MimeMultipart encryptedEmail, AsymmetricCipher recipientKeyPair, AsymmetricCipher senderKeyPair) throws Exception {
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
        SymmetricCipher sessionCrypt = new MyCrypt(sessionSecret);
        String signedMessagePayload = sessionCrypt.decrypt(encryptedPayload);

        // 3. Extract message and signature using the LAST occurrence of the delimiter
        String delimiter = "\n\n---SIGNATURE---\n";
        int lastIndex = signedMessagePayload.lastIndexOf(delimiter);
        if (lastIndex == -1) {
            throw new SecurityException("Invalid secure email format.");
        }
        String messageBody = signedMessagePayload.substring(0, lastIndex);
        String signature = signedMessagePayload.substring(lastIndex + delimiter.length());

        // 4. Verify the signature using sender's Public Key
        boolean isSignatureValid = senderKeyPair.isSignatureValid(messageBody, signature);

        return new DecryptedEmail(messageBody, isSignatureValid);
    }

    /**
     * Simple wrapper to hold the results of decryption and signature verification.
     */
    public static class DecryptedEmail {
        /**
         * The decrypted plaintext message.
         */
        private final String message;

        /**
         * Whether the signature was validly verified against the sender's public key.
         */
        private final boolean validSignature;

        /**
         * Constructs a new DecryptedEmail object.
         * 
         * @param message The decrypted plaintext message.
         * @param validSignature Whether the signature is valid.
         */
        public DecryptedEmail(String message, boolean validSignature) {
            this.message = message;
            this.validSignature = validSignature;
        }

        /**
         * Gets the decrypted message.
         * 
         * @return The message String.
         */
        public String getMessage() { return message; }

        /**
         * Checks if the digital signature was valid.
         * 
         * @return true if the signature is valid; false otherwise.
         */
        public boolean isSignatureValid() { return validSignature; }
    }
}
