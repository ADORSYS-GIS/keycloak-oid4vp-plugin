package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import org.keycloak.common.VerificationException;

public class EudiPidTrustException extends VerificationException {

    public EudiPidTrustException(String message) {
        super(message);
    }

    public EudiPidTrustException(String message, Throwable cause) {
        super(message, cause);
    }
}
