package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * Produces safe client-facing error descriptions while keeping detailed reasons in server logs.
 */
public final class ErrorResponseSanitizer {

    private static volatile OID4VPConfig config = new OID4VPConfig(null);

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

    public static synchronized void init(OID4VPConfig config) {
        ErrorResponseSanitizer.config = Objects.requireNonNull(config);
    }

    public static String correlationIdFromAuthSession(AuthenticationSessionModel authSession) {
        return Optional.ofNullable(authSession)
                .map(OID4VPUserAuthEndpointBase::getAuthSessionId)
                .orElseGet(ErrorResponseSanitizer::newCorrelationId);
    }

    public static String clientDescription(String generic, String detailed, String correlationId) {
        if (config.verboseErrors()) {
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
}
