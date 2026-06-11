package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Resolves DCQL claim paths for presentation validation (VC root, not VP wrapper).
 *
 * <p><strong>Scope:</strong> Only JSON object property names ({@code List<String>} segments) are
 * supported. OpenID4VP 1.0 Claims Path Pointers for JSON credentials also allow {@code null} array
 * wildcards and non-negative integer array indexes; those are not modeled or resolved here yet.
 */
public final class ClaimPathResolver {

    private ClaimPathResolver() {}

    public static boolean isPresentInJson(JsonNode root, List<Object> path) {
        return isPresent(resolveInPayload(root, path));
    }

    public static boolean isPresentInSdJwt(SdJwtVP sdJwt, List<Object> path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        JsonNode resolved = resolveInPayload(sdJwt.getIssuerSignedJWT().getPayload(), path);
        if (isPresent(resolved)) {
            return true;
        }

        if (path.size() == 1) {
            return hasDisclosedClaim(sdJwt, pathSegmentAsString(path.getFirst()));
        }

        return false;
    }

    private static JsonNode resolveInPayload(JsonNode root, List<Object> path) {
        JsonNode current = root;
        for (Object segment : path) {
            String propertyName = pathSegmentAsString(segment);
            if (current == null || current.isNull()) {
                return null;
            }
            current = current.get(propertyName);
        }
        return current;
    }

    private static String pathSegmentAsString(Object segment) {
        if (segment instanceof String propertyName) {
            return propertyName;
        }
        throw new IllegalArgumentException(
                "Claim path supports object property name segments only; unsupported segment: " + segment);
    }

    private static boolean hasDisclosedClaim(SdJwtVP sdJwt, String claimName) {
        for (String disclosure : sdJwt.getDisclosuresString()) {
            try {
                ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
                if (arrayNode.size() == 3 && arrayNode.get(1).asText().equals(claimName)) {
                    return isPresent(arrayNode.get(2));
                }
            } catch (VerificationException ignored) {
                // skip malformed disclosure
            }
        }
        return false;
    }

    private static boolean isPresent(JsonNode node) {
        return node != null && !node.isNull() && !node.isMissingNode();
    }
}
