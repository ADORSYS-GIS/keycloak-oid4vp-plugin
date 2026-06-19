package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Reads claims from issuer-signed and selectively disclosed SD-JWT VC content.
 */
public final class SdJwtCredentialClaims {

    private static final Logger logger = Logger.getLogger(SdJwtCredentialClaims.class);

    private SdJwtCredentialClaims() {}

    public static String readClaim(SdJwtVP sdJwt, String claimName) {
        JsonNode issuerSignedJwtPayload = sdJwt.getIssuerSignedJWT().getPayload();
        JsonNode claim = issuerSignedJwtPayload.get(claimName);

        if (claim == null) {
            claim = readSelectivelyDisclosedClaim(sdJwt, claimName);
        }

        return claim != null ? claim.asText() : null;
    }

    private static JsonNode readSelectivelyDisclosedClaim(SdJwtVP sdJwt, String claimName) {
        for (String disclosure : sdJwt.getDisclosuresString()) {
            try {
                ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
                if (arrayNode.size() == 3 && arrayNode.get(1).asText().equals(claimName)) {
                    return arrayNode.get(2);
                }
            } catch (VerificationException e) {
                logger.warnf(e, "Failed to decode disclosure string");
            }
        }

        return null;
    }
}
