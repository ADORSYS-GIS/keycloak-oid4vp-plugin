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

    public static boolean isPresentInJson(JsonNode root, List<Object> path) {
        return !resolveInJson(root, path).isEmpty();
    }

    public static boolean isPresentInSdJwt(SdJwtVP sdJwt, List<Object> path) {
        return !resolveInSdJwt(sdJwt, path).isEmpty();
    }

    public static List<JsonNode> resolveInSdJwt(SdJwtVP sdJwt, List<Object> path) {
        if (path == null || path.isEmpty()) {
            return List.of();
        }

        List<JsonNode> resolved = resolveInJson(sdJwt.getIssuerSignedJWT().getPayload(), path);
        if (!resolved.isEmpty()) {
            return resolved;
        }

        if (path.getFirst() instanceof String claimName) {
            JsonNode disclosedClaim = findDisclosedClaim(sdJwt, claimName);
            if (isPresent(disclosedClaim)) {
                if (path.size() == 1) {
                    return List.of(disclosedClaim);
                }
                return resolveInJson(disclosedClaim, path.subList(1, path.size()));
            }
        }

        return List.of();
    }

    static List<JsonNode> resolveInJson(JsonNode root, List<Object> path) {
        if (root == null || path == null || path.isEmpty()) {
            return List.of();
        }

        List<JsonNode> selected = List.of(root);
        for (Object segment : path) {
            selected = resolvePathSegment(selected, segment);
            if (selected.isEmpty()) {
                return List.of();
            }
        }
        return selected;
    }

    private static List<JsonNode> resolvePathSegment(List<JsonNode> selected, Object segment) {
        if (segment instanceof String key) {
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
            return next;
        }

        if (segment == null) {
            List<JsonNode> next = new ArrayList<>();
            for (JsonNode node : selected) {
                if (!node.isArray()) {
                    return List.of();
                }
                node.forEach(next::add);
            }
            return next;
        }

        Integer index = asNonNegativeInteger(segment);
        if (index == null) {
            return List.of();
        }

        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : selected) {
            if (!node.isArray()) {
                return List.of();
            }
            if (index < node.size()) {
                next.add(node.get(index));
            }
        }
        return next;
    }

    private static Integer asNonNegativeInteger(Object segment) {
        if (segment instanceof Integer index) {
            return index >= 0 ? index : null;
        }
        if (segment instanceof Number number) {
            if (number.doubleValue() == Math.floor(number.doubleValue()) && number.longValue() >= 0) {
                return number.intValue();
            }
        }
        return null;
    }

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
