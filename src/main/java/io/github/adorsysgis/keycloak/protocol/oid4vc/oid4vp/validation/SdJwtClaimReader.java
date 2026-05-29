package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Reads claim values from an SD-JWT presentation for DCQL satisfaction checks.
 */
public final class SdJwtClaimReader {

    private SdJwtClaimReader() {}

    /**
     * Reconstructs selectively disclosed claims from the presented SD-JWT disclosures (SD-JWT spec).
     */
    public static ObjectNode disclosedClaimsRoot(SdJwtVP sdJwt) throws VerificationException {
        return SdJwtDisclosedPayloadAssembler.assemble(sdJwt);
    }

    public static List<JsonNode> resolveClaimPath(JsonNode claimsRoot, List<Object> path)
            throws VpTokenValidationException {
        return ClaimsPathProcessor.process(claimsRoot, ClaimsPathProcessor.toPathComponents(path));
    }

    public static List<JsonNode> resolveClaimPath(SdJwtVP sdJwt, List<Object> path) throws VpTokenValidationException {
        try {
            ObjectNode root = disclosedClaimsRoot(sdJwt);
            return resolveClaimPath(root, path);
        } catch (VerificationException e) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "Failed to read disclosed claims from SD-JWT presentation",
                    e);
        }
    }
}
