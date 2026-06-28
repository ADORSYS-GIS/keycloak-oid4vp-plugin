package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import java.util.Collections;
import java.util.Map;

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
public record NamespacedClaims(Map<String, Map<String, Object>> namespaces) {

    public NamespacedClaims {
        namespaces = namespaces == null ? Map.of() : Map.copyOf(namespaces);
    }

    /**
     * @return an unmodifiable view of the per-namespace claims map.
     */
    @Override
    public Map<String, Map<String, Object>> namespaces() {
        return Collections.unmodifiableMap(namespaces);
    }

    /**
     * @return the claims map for the given {@code namespace}, or {@code null} if none was presented.
     */
    public Map<String, Object> namespace(String namespace) {
        return namespaces.get(namespace);
    }
}
