package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Expands W3C VC {@code type} values using {@code @context}, per OpenID4VP 1.0 B.1.1.
 *
 * <p>Uses deterministic term resolution for inline {@code @context} objects and the W3C
 * credentials v1 context URL. Terms not defined in any applicable context are left unchanged,
 * which matches the spec rule for relative types that JSON-LD processing would not alter.
 */
public final class VcJsonLdTypeExpander {

    private static final String W3C_CREDENTIALS_V1_CONTEXT = "https://www.w3.org/2018/credentials/v1";

    private static final Map<String, String> W3C_CREDENTIALS_V1_TERMS =
            Map.of("VerifiableCredential", "https://www.w3.org/2018/credentials#VerifiableCredential");

    private VcJsonLdTypeExpander() {}

    public static Set<String> expandTypes(JsonNode vcRoot) {
        JsonNode typeNode = vcRoot.get("type");
        if (typeNode == null || !typeNode.isArray() || typeNode.isEmpty()) {
            return Set.of();
        }

        Map<String, String> termDefinitions = collectTermDefinitions(vcRoot.get("@context"));
        Set<String> expanded = new HashSet<>();
        typeNode.forEach(node -> {
            String compactType = node.asText();
            expanded.add(termDefinitions.getOrDefault(compactType, compactType));
        });
        return expanded;
    }

    private static Map<String, String> collectTermDefinitions(JsonNode context) {
        Map<String, String> terms = new HashMap<>();
        if (context == null || context.isNull()) {
            return terms;
        }
        if (context.isTextual()) {
            if (W3C_CREDENTIALS_V1_CONTEXT.equals(context.asText())) {
                terms.putAll(W3C_CREDENTIALS_V1_TERMS);
            }
        } else if (context.isArray()) {
            context.forEach(entry -> terms.putAll(collectTermDefinitions(entry)));
        } else if (context.isObject()) {
            context.properties().forEach(entry -> {
                if (!entry.getKey().startsWith("@") && entry.getValue().isTextual()) {
                    terms.put(entry.getKey(), entry.getValue().asText());
                }
            });
        }
        return terms;
    }
}
