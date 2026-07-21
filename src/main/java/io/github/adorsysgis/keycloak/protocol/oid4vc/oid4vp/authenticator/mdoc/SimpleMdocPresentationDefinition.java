package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_DOC_TYPE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_NAME_SPACES;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.utils.StringUtil;

/**
 * Express simple presentation requirements for an mDoc device response.
 *
 * <p>Enforces that the presented payload carries one of the expected docTypes and that
 * every required claim is present. Claims may be namespaced ({@code "namespace/name"})
 * — anchored to a specific namespace — or bare ({@code "name"}) — matched under any
 * namespace.
 */
public class SimpleMdocPresentationDefinition implements PresentationRequirements {

    private final List<String> expectedDocTypes;
    private final List<ClaimReference> requiredClaims;

    public SimpleMdocPresentationDefinition(List<String> expectedDocTypes, List<ClaimReference> requiredClaims) {
        this.expectedDocTypes = expectedDocTypes;
        this.requiredClaims = requiredClaims;
    }

    @Override
    public void checkIfSatisfiedBy(JsonNode payload) throws VerificationException {
        String docType = payload.path(L_DOC_TYPE).asText(null);
        if (docType == null || !expectedDocTypes.contains(docType)) {
            throw new VerificationException(
                    String.format("Unexpected docType: expected one of %s but got '%s'", expectedDocTypes, docType));
        }

        JsonNode nameSpaces = payload.get(L_NAME_SPACES);

        for (ClaimReference claim : requiredClaims) {
            JsonNode node = findClaim(claim, nameSpaces);
            if (node == null || node.isNull()) {
                throw new VerificationException(String.format("Missing required claim: %s", claim));
            }
            if (StringUtil.isBlank(node.asText(null))) {
                throw new VerificationException(String.format("Required claim is blank: %s", claim));
            }
        }
    }

    static JsonNode findClaim(ClaimReference claim, JsonNode nameSpaces) {
        if (nameSpaces == null || nameSpaces.isNull()) {
            return null;
        }

        if (claim.isNamespaced()) {
            JsonNode ns = nameSpaces.get(claim.namespace());
            return ns != null ? ns.get(claim.name()) : null;
        }

        var nsNames = nameSpaces.fieldNames();
        while (nsNames.hasNext()) {
            JsonNode ns = nameSpaces.get(nsNames.next());
            if (ns != null && ns.has(claim.name())) {
                return ns.get(claim.name());
            }
        }
        return null;
    }
}
