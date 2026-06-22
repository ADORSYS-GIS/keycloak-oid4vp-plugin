package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Resolves DCQL claim paths for presentation validation (VC root, not VP wrapper).
 */
public final class ClaimPathResolver {

    private ClaimPathResolver() {}

    public static boolean isPresentInJson(JsonNode root, List<String> path) {
        return !resolveInJson(root, path).isEmpty();
    }

    public static boolean isPresentInSdJwt(SdJwtVP sdJwt, List<String> path) {
        return !resolveInSdJwt(sdJwt, path).isEmpty();
    }

    public static List<JsonNode> resolveInSdJwt(SdJwtVP sdJwt, List<String> path) {
        if (path == null || path.isEmpty()) {
            return List.of();
        }

        List<JsonNode> resolved = resolveInJson(sdJwt.getIssuerSignedJWT().getPayload(), path);
        if (!resolved.isEmpty()) {
            return resolved;
        }

        JsonNode disclosedClaim = findDisclosedClaim(sdJwt, path.getFirst());
        if (isPresent(disclosedClaim)) {
            if (path.size() == 1) {
                return List.of(disclosedClaim);
            }
            return resolveInJson(disclosedClaim, path.subList(1, path.size()));
        }

        return List.of();
    }

    static List<JsonNode> resolveInJson(JsonNode root, List<String> path) {
        if (root == null || path == null || path.isEmpty()) {
            return List.of();
        }

        List<JsonNode> selected = List.of(root);
        for (String key : path) {
            List<JsonNode> next = new ArrayList<>();
            for (JsonNode node : selected) {
                if (!node.isObject()) {
                    return List.of();
                }
                JsonNode child = node.get(key);
                if (isPresent(child)) {
                    next.add(child);
                }
            }
            selected = next;
            if (selected.isEmpty()) {
                return List.of();
            }
        }
        return selected;
    }

    /**
     * Returns the first selectively disclosed claim value matching {@code claimName} in presentation
     * order. When multiple disclosures reuse the same claim name, only the first match is used for
     * path resolution.
     */
    private static JsonNode findDisclosedClaim(SdJwtVP sdJwt, String claimName) {
        for (String disclosure : sdJwt.getDisclosuresString()) {
            JsonNode disclosedValue = decodeDisclosedValue(disclosure, claimName);
            if (isPresent(disclosedValue)) {
                return disclosedValue;
            }
        }
        return null;
    }

    private static JsonNode decodeDisclosedValue(String disclosure, String claimName) {
        try {
            ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
            if (arrayNode.size() == 3 && arrayNode.get(1).asText().equals(claimName)) {
                return arrayNode.get(2);
            }
        } catch (VerificationException ignored) {
            return null;
        }
        return null;
    }

    private static boolean isPresent(JsonNode node) {
        return node != null && !node.isNull() && !node.isMissingNode();
    }
}
