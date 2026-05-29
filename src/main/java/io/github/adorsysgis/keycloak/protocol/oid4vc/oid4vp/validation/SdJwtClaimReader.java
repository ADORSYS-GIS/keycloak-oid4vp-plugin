package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Reads claim values from an SD-JWT presentation for DCQL satisfaction checks.
 */
public final class SdJwtClaimReader {

    private SdJwtClaimReader() {}

    public static ObjectNode disclosedClaimsRoot(SdJwtVP sdJwt) throws VerificationException {
        Map<String, JsonNode> claims = new LinkedHashMap<>();
        for (String disclosure : sdJwt.getDisclosuresString()) {
            ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
            if (arrayNode.size() == 3) {
                claims.put(arrayNode.get(1).asText(), arrayNode.get(2));
            }
        }
        ObjectNode root = com.fasterxml.jackson.databind.node.JsonNodeFactory.instance.objectNode();
        claims.forEach(root::set);
        return root;
    }

    public static List<JsonNode> resolveClaimPath(JsonNode claimsRoot, List<Object> path)
            throws VpTokenValidationException {
        return ClaimsPathProcessor.process(claimsRoot, ClaimsPathProcessor.toPathComponents(path));
    }

    public static List<JsonNode> resolveClaimPath(SdJwtVP sdJwt, List<Object> path) throws VpTokenValidationException {
        try {
            JsonNode issuerPayload = sdJwt.getIssuerSignedJWT().getPayload();
            ObjectNode root = ClaimsPathProcessor.credentialClaimsRoot(issuerPayload, disclosedClaimsRoot(sdJwt));
            return resolveClaimPath(root, path);
        } catch (VerificationException e) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "Failed to read disclosed claims from SD-JWT presentation",
                    e);
        }
    }
}
