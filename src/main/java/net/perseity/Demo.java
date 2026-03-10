package net.perseity;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.Provider.Service;
import java.security.spec.InvalidKeySpecException;
import java.util.Set;
import java.util.TreeSet;


public class Demo {
    private static final Logger LOGGER = LogManager.getLogger(Demo.class);
    private static final boolean DEBUG = false;

    public static void main(String[] args) throws RuntimeException {
        if (DEBUG) {
            // display available algorithms
            try {
                Set<String> cipherAlgorithms = new TreeSet<>();
                for (Provider provider : Security.getProviders()) {
                    provider.getServices().stream().filter(s -> "Cipher".equals(s.getType())).map(Service::getAlgorithm)
                            .forEach(cipherAlgorithms::add);
                }
                LOGGER.debug("Ciphers:");
                cipherAlgorithms.forEach(LOGGER::debug);

                TreeSet<String> sigAlgorithms = new TreeSet<>();
                for (Provider provider : Security.getProviders()) {
                    provider.getServices().stream().filter(s -> "Signature".equals(s.getType())).map(
                                Service::getAlgorithm)
                            .forEach(sigAlgorithms::add);
                }
                LOGGER.debug("Signatures:");
                sigAlgorithms.forEach(LOGGER::debug);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        // main processing
        try {
            LOGGER.info("Started...");

            LOGGER.info("Creating sender and recipient key pairs...");
            MyKeyPair myKeyPair = new MyKeyPair();
            Helper.saveKeyPair(myKeyPair, "myKey.pub", "myKey.key");
            Helper.loadKeyPair(myKeyPair, "myKey.pub", "myKey.key");
            LOGGER.info("(myKey) Private KeyID: {}", myKeyPair.getPrivateKeyId());
            LOGGER.info("(myKey) Public KeyID: {}", myKeyPair.getPublicKeyId());

            MyKeyPair yourKeyPair = new MyKeyPair();
            Helper.saveKeyPair(yourKeyPair, "yourKey.pub", "yourKey.key");
            Helper.loadKeyPair(yourKeyPair, "yourKey.pub", "yourKey.key");
            LOGGER.info("(yourKey) Private KeyID: {}", yourKeyPair.getPrivateKeyId());
            LOGGER.info("(yourKey) Public KeyID: {}", yourKeyPair.getPublicKeyId());

            System.out.println();
            LOGGER.info("Sender creates shared secret...");
            MyCrypt myCrypt = new MyCrypt();
            String sharedSecret = myCrypt.getSecretKey();
            LOGGER.info("Shared Secret: {}", sharedSecret);

            LOGGER.info("Sender encrypts shared secret using the recipient's public key...");
            String encryptedSharedSecret = yourKeyPair.encrypt(sharedSecret);
            LOGGER.info("Encrypted Secret: {}", encryptedSharedSecret);
            LOGGER.info("Sender exchanges encrypted shared secret with recipient...\n");

            LOGGER.info("Recipient decrypts shared secret using their private key...");
            String decryptedSharedSecret = yourKeyPair.decrypt(encryptedSharedSecret);
            LOGGER.info("Decrypted Secret: {}", decryptedSharedSecret);

            LOGGER.info("Recipient encrypts secret message using the decrypted shared secret...");
            MyCrypt yourCrypt = new MyCrypt(decryptedSharedSecret);
            String message = "This is a secret message";
            String encrypted = yourCrypt.encrypt(message);
            LOGGER.info("Encrypted Message: {}", encrypted);

            LOGGER.info("Recipient signs secret message using their private key...");
            String signature = yourKeyPair.sign(encrypted);
            LOGGER.info("Signature: {}", signature);
            LOGGER.info("Recipient exchanges encrypted message and signature with original sender...\n");

            LOGGER.info("Original sender verifies the signature is valid...");
            boolean isVerified = yourKeyPair.isSignatureValid(encrypted, signature);
            if (isVerified) {
                LOGGER.info("Signature is verified");
            } else {
                LOGGER.warn("Signature is not verified");
            }
            LOGGER.info("Original sender decrypts the encrypted secret message...");
            String decrypted = myCrypt.decrypt(encrypted);
            LOGGER.info("Decrypted Message: {}", decrypted);
            assert message.equals(decrypted);
        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | IOException | InvalidKeySpecException | BadPaddingException |
                 SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } finally {
            LOGGER.info("Finished.");
        }
    }
}