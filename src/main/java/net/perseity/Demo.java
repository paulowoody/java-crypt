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
                    provider.getServices().stream().filter(s -> "Cipher".equals(s.getType())).map(Service::getAlgorithm).forEach(cipherAlgorithms::add);
                }
                LOGGER.debug("Ciphers:");
                cipherAlgorithms.forEach(LOGGER::debug);

                TreeSet<String> sigAlgorithms = new TreeSet<>();
                for (Provider provider : Security.getProviders()) {
                    provider.getServices().stream().filter(s -> "Signature".equals(s.getType())).map(Service::getAlgorithm).forEach(sigAlgorithms::add);
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
            System.out.println();
            LOGGER.info("=== 1. RSA Key Pair Generation ===");
            LOGGER.info("[Alice] and [Bob] want to communicate securely over the internet.");
            LOGGER.info("[Alice] generates her personal RSA key pair (Public/Private keys)...");
            MyKeyPair myKeyPair = new MyKeyPair();
            Helper.saveKeyPair(myKeyPair, "myKey.pub", "myKey.key");
            Helper.loadKeyPair(myKeyPair, "myKey.pub", "myKey.key");
            LOGGER.info("(Alice) Private KeyID: {}", myKeyPair.getPrivateKeyId());
            LOGGER.info("(Alice) Public KeyID: {}", myKeyPair.getPublicKeyId());

            LOGGER.info("[Bob] generates his personal RSA key pair...");
            MyKeyPair yourKeyPair = new MyKeyPair();
            Helper.saveKeyPair(yourKeyPair, "yourKey.pub", "yourKey.key");
            Helper.loadKeyPair(yourKeyPair, "yourKey.pub", "yourKey.key");
            LOGGER.info("(Bob) Private KeyID: {}", yourKeyPair.getPrivateKeyId());
            LOGGER.info("(Bob) Public KeyID: {}", yourKeyPair.getPublicKeyId());

            System.out.println();
            LOGGER.info("=== 2. Key Exchange (RSA + AES) ===");
            LOGGER.info("[Alice] wants to establish a fast, secure channel with [Bob].");
            LOGGER.info("[Alice] creates a random AES shared secret...");
            MyCrypt myCrypt = new MyCrypt();
            String sharedSecret = myCrypt.getSecretKey();
            LOGGER.info("Shared Secret: {}", sharedSecret);

            LOGGER.info("[Alice] encrypts the shared secret using [Bob]'s public key. Only [Bob] can decrypt it!");
            String encryptedSharedSecret = yourKeyPair.encrypt(sharedSecret);
            LOGGER.info("Encrypted Secret: {}", encryptedSharedSecret);
            LOGGER.info("[Alice] sends the encrypted secret to [Bob] over the public internet...\n");

            LOGGER.info("[Bob] receives the package and decrypts it using his private key...");
            String decryptedSharedSecret = yourKeyPair.decrypt(encryptedSharedSecret);
            LOGGER.info("Decrypted Secret: {}", decryptedSharedSecret);

            System.out.println();
            LOGGER.info("=== 3. Secure Messaging & Digital Signatures ===");
            LOGGER.info("[Bob] wants to send a secret message back to [Alice] using their new shared secret.");
            LOGGER.info("[Bob] encrypts the message with AES...");
            MyCrypt yourCrypt = new MyCrypt(decryptedSharedSecret);
            String message = "This is a secret message";
            String encrypted = yourCrypt.encrypt(message);
            LOGGER.info("Encrypted Message: {}", encrypted);

            LOGGER.info("[Bob] signs the encrypted message with his private key so [Alice] knows it really came from him...");
            String signature = yourKeyPair.sign(encrypted);
            LOGGER.info("Signature: {}", signature);
            LOGGER.info("[Bob] sends the encrypted message and signature to [Alice]...\n");

            LOGGER.info("[Alice] receives the message. First, she verifies the signature using [Bob]'s public key...");
            boolean isVerified = yourKeyPair.isSignatureValid(encrypted, signature);
            if (isVerified) {
                LOGGER.info("[Alice] Signature is verified. The message is authentic.");
            } else {
                LOGGER.warn("[Alice] Signature is not verified. The message may be tampered with!");
            }
            LOGGER.info("[Alice] Now she decrypts the message using their AES shared secret...");
            String decrypted = myCrypt.decrypt(encrypted);
            LOGGER.info("Decrypted Message: {}", decrypted);
            assert message.equals(decrypted);

            System.out.println();
            LOGGER.info("=== 4. Real-World JWT Scenario ===");
            LOGGER.info("[Client] Wants to access their bank account balance, but needs to login first.");
            LOGGER.info("[Client] Sends username and password to the Auth Server...");

            LOGGER.info("[Server] Verifies credentials and generates a short-lived JWT (The 'Session Token')...");
            // We use the shared secret as the server's signing key for this demo
            String clientToken = MyJwt.createToken("alice_user", decryptedSharedSecret);
            LOGGER.info("[Server] Returns JWT to Client: {}", clientToken);

            System.out.println();
            LOGGER.info("[Client] Stores the token securely.");
            LOGGER.info("[Client] Makes an API request: GET /account/balance");
            LOGGER.info("[Client] Attaches the JWT to the request header (e.g., 'Authorization: Bearer <token>')...");

            LOGGER.info("[Server/API] Receives request. Verifying the token signature and expiration...");
            boolean isAuthorized = MyJwt.verifyToken(clientToken, decryptedSharedSecret);
            if (isAuthorized) {
                LOGGER.info("[Server/API] Token is VALID. Returning secure data: { Balance: $1,000,000 }");
            } else {
                LOGGER.warn("[Server/API] Token is INVALID or EXPIRED. Returning 401 Unauthorized.");
            }
            assert isAuthorized;

            System.out.println();
            LOGGER.info("[Hacker] Intercepts the token and tries to change the 'sub' (subject) to 'admin' to steal money...");
            String[] tokenParts = clientToken.split("\\.");
            // Hacker creates a malicious payload but cannot generate a valid signature without the server's secret key
            String tamperedPayload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"admin\",\"exp\":9999999999}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String tamperedToken = tokenParts[0] + "." + tamperedPayload + "." + tokenParts[2];

            LOGGER.info("[Hacker] Sends request: GET /admin/vault with the tampered token...");
            LOGGER.info("[Server/API] Receives request. Verifying the tampered token...");
            boolean isHackerAuthorized = MyJwt.verifyToken(tamperedToken, decryptedSharedSecret);
            if (isHackerAuthorized) {
                LOGGER.error("[Server/API] Uh oh! Hacker got in! This shouldn't happen.");
            } else {
                LOGGER.info("[Server/API] Verification FAILED. The payload was altered but the signature doesn't match! Returning 401 Unauthorized.");
            }
            assert !isHackerAuthorized;

        } catch (InvalidAlgorithmParameterException | NoSuchPaddingException | IllegalBlockSizeException |
                 NoSuchAlgorithmException | IOException | InvalidKeySpecException | BadPaddingException |
                 SignatureException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } finally {
            LOGGER.info("Finished.");
        }
    }
}