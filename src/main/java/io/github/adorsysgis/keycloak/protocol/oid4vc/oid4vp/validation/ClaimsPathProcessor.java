package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Applies DCQL claims path pointers to JSON-based credentials (OpenID4VP §7.1).
 */
public final class ClaimsPathProcessor {

    private ClaimsPathProcessor() {}

    /**
     * @return selected claim values; empty when the path does not resolve
     */
    public static List<JsonNode> process(JsonNode root, List<Object> path) throws VpTokenValidationException {
        if (root == null || path == null || path.isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL, "Claims path pointer must be a non-empty array");
        }

        List<JsonNode> selected = List.of(root);
        for (Object component : path) {
            selected = processComponent(selected, component);
            if (selected.isEmpty()) {
                return List.of();
            }
        }
        return selected;
    }

    private static List<JsonNode> processComponent(List<JsonNode> current, Object component)
            throws VpTokenValidationException {
        if (component instanceof String key) {
            return selectObjectKey(current, key);
        }
        if (component == null) {
            return selectAllArrayElements(current);
        }
        if (component instanceof Integer index) {
            return selectArrayIndex(current, index);
        }
        if (component instanceof Number number) {
            if (number.doubleValue() != Math.floor(number.doubleValue()) || number.longValue() < 0) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL, "Claims path index must be a non-negative integer");
            }
            return selectArrayIndex(current, number.intValue());
        }
        throw new VpTokenValidationException(
                VpTokenValidationException.Phase.DCQL, "Unsupported claims path pointer component: " + component);
    }

    private static List<JsonNode> selectObjectKey(List<JsonNode> current, String key)
            throws VpTokenValidationException {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isObject()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL,
                        "Claims path pointer expected an object at the current selection");
            }
            JsonNode child = node.get(key);
            if (child != null) {
                next.add(child);
            }
        }
        return next;
    }

    private static List<JsonNode> selectAllArrayElements(List<JsonNode> current) throws VpTokenValidationException {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isArray()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL,
                        "Claims path pointer expected an array at the current selection");
            }
            ArrayNode arrayNode = (ArrayNode) node;
            arrayNode.forEach(next::add);
        }
        return next;
    }

    private static List<JsonNode> selectArrayIndex(List<JsonNode> current, int index)
            throws VpTokenValidationException {
        List<JsonNode> next = new ArrayList<>();
        for (JsonNode node : current) {
            if (!node.isArray()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL,
                        "Claims path pointer expected an array at the current selection");
            }
            ArrayNode arrayNode = (ArrayNode) node;
            if (index >= 0 && index < arrayNode.size()) {
                next.add(arrayNode.get(index));
            }
        }
        return next;
    }

    /**
     * Adapts a DCQL {@code path} from {@link io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim}
     * to the mixed components expected by {@link #process} (OpenID4VP §7.1).
     */
    public static List<Object> toPathComponents(List<Object> path) throws VpTokenValidationException {
        if (path == null || path.isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL, "DCQL claim query is missing path");
        }

        List<Object> components = new ArrayList<>(path.size());
        for (Object component : path) {
            components.add(normalizePathComponent(component));
        }
        return Collections.unmodifiableList(components);
    }

    private static Object normalizePathComponent(Object component) throws VpTokenValidationException {
        if (component == null) {
            return null;
        }
        if (component instanceof String key) {
            if (key.isEmpty()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL,
                        "Claims path pointer object key must be a non-empty string");
            }
            return key;
        }
        if (component instanceof Integer index) {
            return normalizeArrayIndex(index);
        }
        if (component instanceof Long index) {
            return normalizeArrayIndex(index);
        }
        if (component instanceof Number number) {
            if (number.doubleValue() != Math.floor(number.doubleValue()) || number.longValue() < 0) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL, "Claims path index must be a non-negative integer");
            }
            if (number.longValue() > Integer.MAX_VALUE) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL, "Claims path index is out of range");
            }
            return number.intValue();
        }
        throw new VpTokenValidationException(
                VpTokenValidationException.Phase.DCQL, "Unsupported claims path pointer component: " + component);
    }

    private static int normalizeArrayIndex(long index) throws VpTokenValidationException {
        if (index < 0 || index > Integer.MAX_VALUE) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL, "Claims path index must be a non-negative integer");
        }
        return (int) index;
    }

    /**
     * Merges issuer-signed payload with selectively disclosed claims for path resolution.
     */
    public static ObjectNode credentialClaimsRoot(JsonNode issuerSignedPayload, JsonNode disclosedClaims) {
        ObjectNode root = issuerSignedPayload.deepCopy();
        if (disclosedClaims != null && disclosedClaims.isObject()) {
            disclosedClaims.properties().forEach(entry -> root.set(entry.getKey(), entry.getValue()));
        }
        return root;
    }
}
