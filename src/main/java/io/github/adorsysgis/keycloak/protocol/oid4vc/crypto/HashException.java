package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

/**
 * Custom exception thrown when a hashing operation fails.
 */
public class HashException extends RuntimeException {
    public HashException(String message, Throwable cause) {
        super(message, cause);
    }
}
