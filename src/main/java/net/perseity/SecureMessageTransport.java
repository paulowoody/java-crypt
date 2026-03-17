package net.perseity;

import javax.mail.internet.MimeMultipart;

/**
 * Defines a high-level contract for secure message transport.
 * Implementations should handle complex flows like signing and encrypting messages.
 * This abstraction allows swapping the current custom implementation with standard
 * protocols like S/MIME (using libraries like BouncyCastle) without changing 
 * consumer code.
 */
public interface SecureMessageTransport {

    /**
     * Signs a message body and encrypts it for a specific recipient.
     *
     * @param messageBody       The plaintext message content.
     * @param sender            The sender's asymmetric cipher (used to sign).
     * @param recipient         The recipient's asymmetric cipher (used to encrypt).
     * @return A MimeMultipart containing the signed and encrypted message.
     * @throws Exception If signing, encryption, or message construction fails.
     */
    MimeMultipart signAndEncrypt(String messageBody, AsymmetricCipher sender, AsymmetricCipher recipient) throws Exception;

    /**
     * Decrypts a secure message and verifies the sender's signature.
     *
     * @param encryptedEmail    The MimeMultipart containing the encrypted data.
     * @param recipient         The recipient's asymmetric cipher (used to decrypt).
     * @param sender            The sender's asymmetric cipher (used to verify).
     * @return A DecryptedEmail object containing the decrypted message and its signature verification status.
     * @throws Exception If decryption, signature verification, or message parsing fails.
     */
    DecryptedEmail decryptAndVerify(MimeMultipart encryptedEmail, AsymmetricCipher recipient, AsymmetricCipher sender) throws Exception;

    /**
     * Simple wrapper to hold the results of decryption and signature verification.
     */
    class DecryptedEmail {
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
