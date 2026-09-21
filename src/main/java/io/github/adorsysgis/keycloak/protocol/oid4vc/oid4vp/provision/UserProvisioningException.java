package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision;

/**
 * Expected user-import failure. The authenticator maps each reason to the matching login-flow
 * failure; failures after the first database write additionally mark the transaction rollback-only
 * and escape instead of producing a normal flow failure.
 */
public class UserProvisioningException extends Exception {

    public enum Reason {
        /** The import provider is missing, disabled, or has an unexpected provider id. */
        NOT_CONFIGURED,
        /** A binding rule rejects the staged values. */
        BINDING,
        /** The staged profile violates the realm user-profile rules. */
        INVALID_PROFILE,
        /** A different account already uses the derived username or email. */
        DUPLICATE
    }

    private final Reason reason;

    public UserProvisioningException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public UserProvisioningException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }
}
