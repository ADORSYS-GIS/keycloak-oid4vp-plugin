package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPConfig;
import java.util.UUID;
import org.jboss.logging.Logger;

/**
 * Produces safe client-facing error descriptions while keeping detailed reasons in server logs.
 */
public final class ErrorResponseSanitizer {

    private static final Logger logger = Logger.getLogger(ErrorResponseSanitizer.class);

    private ErrorResponseSanitizer() {}

    public static String newCorrelationId() {
        return UUID.randomUUID().toString();
    }

    public static String clientDescription(String generic, String detailed, String correlationId) {
        if (OID4VPConfig.verboseErrors()) {
            return detailed;
        }
        return String.format("%s (ref: %s)", generic, correlationId);
    }

    public static void logDetailed(String correlationId, String message, Throwable cause) {
        if (cause != null) {
            logger.errorf(cause, "[%s] %s", correlationId, message);
        } else {
            logger.errorf("[%s] %s", correlationId, message);
        }
    }
}

