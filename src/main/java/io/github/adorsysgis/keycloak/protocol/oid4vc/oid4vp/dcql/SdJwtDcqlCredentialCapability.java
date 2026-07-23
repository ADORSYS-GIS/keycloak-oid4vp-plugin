package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.SdGenericFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/** Production DCQL path for {@code dc+sd-jwt} user authentication. */
public final class SdJwtDcqlCredentialCapability implements DcqlCredentialCapability {

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public void validateCredentialQuery(Credential credential) {
        validateMeta(credential.getMeta());
        validateClaimPaths(credential);
    }

    @Override
    public boolean supportsPresentationPreValidation() {
        return true;
    }

    @Override
    public void validatePresentation(Credential credential, String presentedToken) throws VerificationException {
        if (!format().equals(credential.getFormat())) {
            throw new VerificationException(
                    "Unsupported dcql_query credential format for presentation validation: " + credential.getFormat());
        }

        SdJwtVP presentation = SdJwtVP.of(presentedToken);
        validateHolderBinding(credential, presentation);
        validatePresentedVct(credential.getMeta(), presentation);
        validateRequestedClaims(credential, presentation);
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        SdGenericFormat format = new SdGenericFormat();
        format.setSdJwtAlgValues(signatureAlgorithms);
        format.setKbJwtAlgValues(signatureAlgorithms);
        vpFormat.setDcSdJwt(format);
    }

    private static void validateMeta(Meta meta) {
        if (meta.getVctValues() == null || meta.getVctValues().isEmpty()) {
            throw new IllegalArgumentException("meta.vct_values must be non-empty for dc+sd-jwt credential queries");
        }
        if (meta.getVctValues().stream().anyMatch(StringUtil::isBlank)) {
            throw new IllegalArgumentException("meta.vct_values must not contain blank entries");
        }
    }

    private static void validateClaimPaths(Credential credential) {
        if (credential.getClaims() == null) {
            return;
        }
        credential.getClaims().forEach(claim -> {
            List<String> path = claim.getPath();
            if (path.stream().anyMatch(SdJwtDcqlCredentialCapability::isUnsupportedPathSegment)) {
                throw new IllegalArgumentException(
                        "dcql_query claim path supports object property names only; array indexes and null wildcards are not supported");
            }
        });
    }

    private static boolean isUnsupportedPathSegment(String segment) {
        return "null".equals(segment) || (!segment.isEmpty() && segment.chars().allMatch(Character::isDigit));
    }

    private static void validateHolderBinding(Credential credential, SdJwtVP presentation)
            throws VerificationException {
        Boolean required = credential.getRequireCryptographicHolderBinding();
        if (!Boolean.FALSE.equals(required) && presentation.getKeyBindingJWT().isEmpty()) {
            throw new VerificationException("DCQL query requires cryptographic holder binding (Key Binding JWT)");
        }
    }

    private static void validatePresentedVct(Meta meta, SdJwtVP presentation) throws VerificationException {
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

    private static void validateRequestedClaims(Credential credential, SdJwtVP presentation)
            throws VerificationException {
        if (credential.getClaims() == null || credential.getClaims().isEmpty()) {
            return;
        }

        Map<String, ClaimValidationResult> claimResults = evaluateClaims(credential.getClaims(), presentation);

        List<List<String>> claimSets = credential.getClaimSets();
        if (claimSets == null || claimSets.isEmpty()) {
            for (Claim claim : credential.getClaims()) {
                ClaimValidationResult result = evaluateClaim(claim, presentation);
                if (!result.satisfied()) {
                    throw new VerificationException(result.errorMessage());
                }
            }
            return;
        }

        if (satisfiesAnyClaimSet(claimSets, claimResults)) {
            return;
        }
        throw new VerificationException("Presented SD-JWT does not satisfy any DCQL claim_sets option");
    }

    private static Map<String, ClaimValidationResult> evaluateClaims(List<Claim> claims, SdJwtVP presentation) {
        Map<String, ClaimValidationResult> claimResults = new HashMap<>();
        for (Claim claim : claims) {
            claimResults.put(claim.getId(), evaluateClaim(claim, presentation));
        }
        return claimResults;
    }

    private static boolean satisfiesAnyClaimSet(
            List<List<String>> claimSets, Map<String, ClaimValidationResult> claimResults) {
        return claimSets.stream().anyMatch(option -> option.stream()
                .allMatch(claimId -> claimResults.containsKey(claimId)
                        && claimResults.get(claimId).satisfied()));
    }

    private static ClaimValidationResult evaluateClaim(Claim claim, SdJwtVP presentation) {
        List<JsonNode> selectedClaimValues = ClaimPathResolver.resolveInSdJwt(presentation, claim.getPath());
        if (selectedClaimValues.isEmpty()) {
            return ClaimValidationResult.failed(
                    "Presented SD-JWT does not satisfy DCQL claim path: " + claim.getPath());
        }
        try {
            validateRequestedClaimValues(claim, selectedClaimValues);
            return ClaimValidationResult.ok();
        } catch (VerificationException e) {
            return ClaimValidationResult.failed(e.getMessage());
        }
    }

    private static void validateRequestedClaimValues(Claim claim, List<JsonNode> selectedClaimValues)
            throws VerificationException {
        if (claim.getValues() == null || claim.getValues().isEmpty()) {
            return;
        }

        boolean hasAnyExpectedMatch = claim.getValues().stream()
                .map(JsonSerialization.mapper::valueToTree)
                .anyMatch(expected -> selectedClaimValues.stream().anyMatch(expected::equals));

        if (!hasAnyExpectedMatch) {
            throw new VerificationException(
                    "Presented SD-JWT does not satisfy DCQL claim values for path: " + claim.getPath());
        }
    }

    private record ClaimValidationResult(boolean satisfied, String errorMessage) {
        private static ClaimValidationResult ok() {
            return new ClaimValidationResult(true, null);
        }

        private static ClaimValidationResult failed(String errorMessage) {
            return new ClaimValidationResult(false, errorMessage);
        }
    }
}
