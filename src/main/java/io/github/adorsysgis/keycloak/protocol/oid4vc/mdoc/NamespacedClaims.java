package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.Map;
import org.keycloak.util.JsonSerialization;

/**
 * Claims presented in mDoc device response, parsed into a succinct structure.
 *
 * <p>Each namespace maps to a {@code Map<String, Object>} whose keys are element
 * identifiers and whose values are the corresponding element values (any JSON type).
 *
 * <p>Example shape:
 * <pre>
 * {
 *   "ns1": { "k1": v1, "k2": v2 },
 *   "ns2": { "k1": v1, "k2": v2 }
 * }
 * </pre>
 */
public record NamespacedClaims(String docType, Map<String, Map<String, Object>> namespaces) {

    public NamespacedClaims {
        namespaces = namespaces == null ? Map.of() : Collections.unmodifiableMap(namespaces);
    }

    public JsonNode toJson() {
        return JsonSerialization.writeValueAsNode(Map.of(
                MdocConstants.L_DOC_TYPE, docType,
                MdocConstants.L_NAME_SPACES, namespaces));
    }
}
