package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

/**
 * Raised when a returned {@code vp_token} or contained presentation fails verifier-side validation.
 */
public class VpTokenValidationException extends Exception {

    public enum Phase {
        STRUCTURE,
        FORMAT,
        DCQL
    }

    private final Phase phase;

    public VpTokenValidationException(Phase phase, String message) {
        super(message);
        this.phase = phase;
    }

    public VpTokenValidationException(Phase phase, String message, Throwable cause) {
        super(message, cause);
        this.phase = phase;
    }

    public Phase getPhase() {
        return phase;
    }
}
