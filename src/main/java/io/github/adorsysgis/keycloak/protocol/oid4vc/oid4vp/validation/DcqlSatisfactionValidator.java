package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.VCFormat;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Verifies that validated presentations satisfy the issued DCQL query (OpenID4VP §6.4, §8.6).
 *
 * <p>The wallet may have enforced DCQL already; the verifier MUST NOT rely on that.
 */
public class DcqlSatisfactionValidator {

    public void validate(List<PresentedCredential> presentations, DcqlQuery dcqlQuery)
            throws VpTokenValidationException {
        Map<String, PresentedCredential> presentedById = new HashMap<>();
        for (PresentedCredential presented : presentations) {
            presentedById.put(presented.credentialQueryId(), presented);
        }

        if (!DcqlQueryRules.usesCredentialSets(dcqlQuery)) {
            DcqlQueryRules.requireAllCredentialQueriesPresent(
                    presentedById, dcqlQuery, VpTokenValidationException.Phase.DCQL);
        } else {
            DcqlQueryRules.validateRequiredCredentialSets(
                    presentedById, dcqlQuery, VpTokenValidationException.Phase.DCQL);
            DcqlQueryRules.validatePresentedCredentialsWithinCredentialSets(
                    presentedById, dcqlQuery, VpTokenValidationException.Phase.DCQL);
        }

        for (PresentedCredential presented : presentations) {
            validateCredentialQuery(presented.presentation(), presented.credentialQuery());
        }
    }

    private void validateCredentialQuery(SdJwtVP presentation, Credential credentialQuery)
            throws VpTokenValidationException {
        validateFormat(credentialQuery);
        validateMeta(presentation, credentialQuery.getMeta());
        validateClaims(presentation, credentialQuery);
    }

    private void validateFormat(Credential credentialQuery) throws VpTokenValidationException {
        String expectedFormat = credentialQuery.getFormat();
        if (expectedFormat == null || expectedFormat.isBlank()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL, "DCQL credential query is missing format");
        }
        if (!VCFormat.SD_JWT_VC.equals(expectedFormat) && !"dc+sd-jwt".equals(expectedFormat)) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "Unsupported credential format in DCQL query: " + expectedFormat);
        }
    }

    private void validateMeta(SdJwtVP presentation, Meta meta) throws VpTokenValidationException {
        if (meta == null || meta.getVctValues() == null || meta.getVctValues().isEmpty()) {
            return;
        }

        String presentedVct = readScalarClaim(presentation, CLAIM_NAME_VCT);
        if (presentedVct == null) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL, "Presentation is missing required vct claim");
        }
        if (!meta.getVctValues().contains(presentedVct)) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "Presentation vct does not match any value requested in DCQL meta.vct_values");
        }
    }

    private void validateClaims(SdJwtVP presentation, Credential credentialQuery) throws VpTokenValidationException {
        List<Claim> claims = credentialQuery.getClaims();
        if (claims == null || claims.isEmpty()) {
            return;
        }

        if (credentialQuery.getClaimSets() != null
                && !credentialQuery.getClaimSets().isEmpty()) {
            validateClaimSets(presentation, credentialQuery, claims);
            return;
        }

        for (Claim claimQuery : claims) {
            requireClaimPath(presentation, claimQuery);
        }
    }

    private void validateClaimSets(SdJwtVP presentation, Credential credentialQuery, List<Claim> claims)
            throws VpTokenValidationException {
        Map<String, Claim> claimsById = new HashMap<>();
        for (Claim claim : claims) {
            if (claim.getId() == null || claim.getId().isBlank()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL, "DCQL claim id is required when claim_sets are present");
            }
            claimsById.put(claim.getId(), claim);
        }

        for (List<String> option : credentialQuery.getClaimSets()) {
            if (satisfiesClaimSetOption(presentation, claimsById, option)) {
                return;
            }
        }

        throw new VpTokenValidationException(
                VpTokenValidationException.Phase.DCQL,
                "Presentation does not satisfy any requested DCQL claim_sets option");
    }

    private boolean satisfiesClaimSetOption(SdJwtVP presentation, Map<String, Claim> claimsById, List<String> option)
            throws VpTokenValidationException {
        for (String claimId : option) {
            Claim claimQuery = claimsById.get(claimId);
            if (claimQuery == null) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.DCQL,
                        "DCQL claim_sets references unknown claim id: " + claimId);
            }
            if (!hasClaimPath(presentation, claimQuery)) {
                return false;
            }
        }
        return true;
    }

    private void requireClaimPath(SdJwtVP presentation, Claim claimQuery) throws VpTokenValidationException {
        if (!hasClaimPath(presentation, claimQuery)) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "Presentation does not contain claim required by DCQL path: " + claimQuery.getPath());
        }
    }

    private boolean hasClaimPath(SdJwtVP presentation, Claim claimQuery) throws VpTokenValidationException {
        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(presentation, claimQuery.getPath());
        if (resolved.isEmpty()) {
            return false;
        }
        return DcqlClaimValues.matchesAny(resolved, claimQuery.getValues());
    }

    private String readScalarClaim(SdJwtVP presentation, String claimName) throws VpTokenValidationException {
        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(presentation, List.of(claimName));
        if (resolved.isEmpty()) {
            return null;
        }
        JsonNode value = resolved.getFirst();
        return value.isValueNode() ? value.asText() : value.toString();
    }
}
