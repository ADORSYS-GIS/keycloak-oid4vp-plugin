package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Resolves DCQL claim paths against presented SD-JWT credentials (VC root, not VP wrapper).
 */
public final class ClaimPathResolver {

    private ClaimPathResolver() {}

    public static boolean isPresentInJson(JsonNode root, List<String> path) {
        return isPresent(resolveInPayload(root, path));
    }

    public static boolean isPresentInSdJwt(SdJwtVP sdJwt, List<String> path) {
        if (path == null || path.isEmpty()) {
            return false;
        }

        JsonNode resolved = resolveInPayload(sdJwt.getIssuerSignedJWT().getPayload(), path);
        if (isPresent(resolved)) {
            return true;
        }

        if (path.size() == 1) {
            return hasDisclosedClaim(sdJwt, path.getFirst());
        }

        return false;
    }

    private static JsonNode resolveInPayload(JsonNode root, List<String> path) {
        JsonNode current = root;
        for (String segment : path) {
            if (current == null || current.isNull()) {
                return null;
            }
            current = current.get(segment);
        }
        return current;
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
