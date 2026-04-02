package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import java.util.UUID;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Produces safe client-facing error descriptions while keeping detailed reasons in server logs.
 */
public final class ErrorResponseSanitizer {

    private final String correlationId;

    private ErrorResponseSanitizer(String correlationId) {
        this.correlationId = correlationId;
    }

    /**
     * Creates a sanitizer bound to a specific correlation id to avoid passing it around.
     */
    public static ErrorResponseSanitizer withCorrelationId(String correlationId) {
        return new ErrorResponseSanitizer(correlationId);
    }

    public static String newCorrelationId() {
        return UUID.randomUUID().toString();
    }

    public static String correlationIdFromAuthSession(AuthenticationSessionModel authSession) {
        if (authSession == null) {
            return newCorrelationId();
        }
        return OID4VPUserAuthEndpointBase.getAuthSessionId(authSession);
    }

    public static String correlationIdFromState(String state) {
        try {
            return OID4VPUserAuthEndpointBase.pruneAuthSessionId(state);
        } catch (IllegalArgumentException e) {
            return newCorrelationId();
        }
    }

    public static String clientDescription(String generic, String detailed, String correlationId) {
        if (OID4VPConfig.verboseErrors()) {
            return String.format("%s (ref: %s)", detailed, correlationId);
        }
        return String.format("%s (ref: %s)", generic, correlationId);
    }

    public String clientDescription(String generic, String detailed) {
        return clientDescription(generic, detailed, correlationId);
    }

    public String correlationId() {
        return correlationId;
    }

    /**
     * Client-facing text for an {@link OAuth2ErrorRepresentation} produced by the SD-JWT authenticator.
     */
    public static String authenticatorOAuth2ClientMessage(OAuth2ErrorRepresentation error, String correlationId) {
        if (OID4VPConfig.verboseErrors()) {
            return String.format(
                    "%s: %s (ref: %s)", error.getError().toUpperCase(), error.getErrorDescription(), correlationId);
        }
        return withCorrelationId(correlationId)
                .clientDescription("Invalid SD-JWT presentation", error.getErrorDescription());
    }
}
