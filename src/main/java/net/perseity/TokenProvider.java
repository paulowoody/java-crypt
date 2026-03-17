package net.perseity;

/**
 * Defines the contract for generating and verifying security tokens (like JWT).
 * Introducing this interface allows the library to support multiple token standards
 * or different signing algorithms in a pluggable way.
 */
public interface TokenProvider {

    /**
     * Generates a new signed security token for a given subject.
     *
     * @param subject The identity being authenticated (e.g., user ID).
     * @param secret  The shared secret key used to sign the token.
     * @return A signed token string.
     * @throws Exception If token creation fails.
     */
    String createToken(String subject, String secret) throws Exception;

    /**
     * Verifies the structure, cryptographic signature, and validity of a given token.
     * 
     * @param token  The token string to verify.
     * @param secret The shared secret key expected to have been used to sign the token.
     * @return True if the token is valid; false otherwise.
     */
    boolean verifyToken(String token, String secret);
}
