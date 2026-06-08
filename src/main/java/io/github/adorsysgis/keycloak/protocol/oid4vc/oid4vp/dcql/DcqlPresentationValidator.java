package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.utils.StringUtil;

/**
 * Validates that a presented credential satisfies the DCQL constraints from the authorization request.
 */
public final class DcqlPresentationValidator {

    private DcqlPresentationValidator() {}

    public static void validatePresentation(DcqlQuery query, String presentedToken) throws VerificationException {
        DcqlQueryValidator.validateQuery(query);
        if (query.getCredentials().size() != 1) {
            throw new VerificationException(
                    "Only single-credential DCQL queries are supported for presentation validation");
        }

        Credential credentialQuery = query.getCredentials().getFirst();
        if (!VCFormat.SD_JWT_VC.equals(credentialQuery.getFormat())) {
            throw new VerificationException("Unsupported dcql_query credential format for presentation validation: "
                    + credentialQuery.getFormat());
        }
        validateSdJwtPresentation(query, SdJwtVP.of(presentedToken));
    }

    private static void validateSdJwtPresentation(DcqlQuery query, SdJwtVP presentation) throws VerificationException {
        Credential credentialQuery = query.getCredentials().getFirst();
        validateHolderBinding(credentialQuery, presentation);
        validateSdJwtMeta(credentialQuery.getMeta(), presentation);
        validateSdJwtRequestedClaims(credentialQuery, presentation);
    }

    private static void validateHolderBinding(Credential credentialQuery, SdJwtVP presentation)
            throws VerificationException {
        Boolean required = credentialQuery.getRequireCryptographicHolderBinding();
        if (Boolean.TRUE.equals(required) && presentation.getKeyBindingJWT().isEmpty()) {
            throw new VerificationException("DCQL query requires cryptographic holder binding (Key Binding JWT)");
        }
    }

    private static void validateSdJwtMeta(Meta meta, SdJwtVP presentation) throws VerificationException {
        JsonNode payload = presentation.getIssuerSignedJWT().getPayload();
        JsonNode vctNode = payload.get(CLAIM_NAME_VCT);
        if (vctNode == null || vctNode.isNull() || StringUtil.isBlank(vctNode.asText())) {
            throw new VerificationException("Presented SD-JWT is missing required vct claim");
        }

        String presentedVct = vctNode.asText();
        boolean matches = meta.getVctValues().stream().anyMatch(expected -> expected.equals(presentedVct));
        if (!matches) {
            throw new VerificationException(
                    "Presented SD-JWT vct does not match any value in meta.vct_values: " + presentedVct);
        }
    }

    private static void validateSdJwtRequestedClaims(Credential credentialQuery, SdJwtVP presentation)
            throws VerificationException {
        if (credentialQuery.getClaims() == null || credentialQuery.getClaims().isEmpty()) {
            return;
        }

        for (Claim claim : credentialQuery.getClaims()) {
            if (!ClaimPathResolver.isPresentInSdJwt(presentation, claim.getPath())) {
                throw new VerificationException(
                        "Presented SD-JWT does not satisfy DCQL claim path: " + claim.getPath());
            }
        }
    }
}
