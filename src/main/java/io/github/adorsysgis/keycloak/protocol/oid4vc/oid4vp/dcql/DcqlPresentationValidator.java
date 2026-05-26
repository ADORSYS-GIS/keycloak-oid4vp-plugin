package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_VCT;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.Set;
import org.keycloak.VCFormat;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.utils.StringUtil;

/**
 * Validates that a presented credential satisfies the DCQL constraints from the authorization request.
 */
public final class DcqlPresentationValidator {

    private static final String VP_ENVELOPE_CLAIM = "vp";
    private static final String VP_VERIFIABLE_CREDENTIAL_CLAIM = "verifiableCredential";
    private static final String JWT_VC_CLAIM = "vc";

    private DcqlPresentationValidator() {}

    public static void validatePresentation(DcqlQuery query, String presentedToken) throws VerificationException {
        DcqlQueryValidator.validateQuery(query);
        if (query.getCredentials().size() != 1) {
            throw new VerificationException(
                    "Only single-credential DCQL queries are supported for presentation validation");
        }

        Credential credentialQuery = query.getCredentials().getFirst();
        switch (credentialQuery.getFormat()) {
            case VCFormat.SD_JWT_VC -> validateSdJwtPresentation(query, SdJwtVP.of(presentedToken));
            case VCFormat.JWT_VC -> validateJwtVcJsonPresentation(query, presentedToken);
            default ->
                throw new VerificationException("Unsupported dcql_query credential format for presentation validation: "
                        + credentialQuery.getFormat());
        }
    }

    public static void validateSdJwtPresentation(DcqlQuery query, SdJwtVP presentation) throws VerificationException {
        DcqlQueryValidator.validateQuery(query);
        if (query.getCredentials().size() != 1) {
            throw new VerificationException(
                    "Only single-credential DCQL queries are supported for SD-JWT presentation validation");
        }

        Credential credentialQuery = query.getCredentials().getFirst();
        if (!VCFormat.SD_JWT_VC.equals(credentialQuery.getFormat())) {
            throw new VerificationException(
                    "Expected dc+sd-jwt credential query but found: " + credentialQuery.getFormat());
        }

        validateHolderBinding(credentialQuery, presentation);
        validateSdJwtMeta(credentialQuery.getMeta(), presentation);
        validateSdJwtRequestedClaims(credentialQuery, presentation);
    }

    public static void validateJwtVcJsonPresentation(DcqlQuery query, String presentedVpJwt)
            throws VerificationException {
        DcqlQueryValidator.validateQuery(query);
        if (query.getCredentials().size() != 1) {
            throw new VerificationException(
                    "Only single-credential DCQL queries are supported for jwt_vc_json presentation validation");
        }

        Credential credentialQuery = query.getCredentials().getFirst();
        if (!VCFormat.JWT_VC.equals(credentialQuery.getFormat())) {
            throw new VerificationException(
                    "Expected jwt_vc_json credential query but found: " + credentialQuery.getFormat());
        }

        JsonNode vpPayload = parseJwtPayload(presentedVpJwt);
        JsonNode vcPayload = extractVcPayload(vpPayload);
        validateJwtVcJsonMeta(credentialQuery.getMeta(), vcPayload);
        validateJwtVcJsonRequestedClaims(credentialQuery, vcPayload);
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

    private static void validateJwtVcJsonMeta(Meta meta, JsonNode vcPayload) throws VerificationException {
        JsonNode typeNode = vcPayload.get("type");
        if (typeNode == null || !typeNode.isArray() || typeNode.isEmpty()) {
            throw new VerificationException("Presented jwt_vc_json credential is missing required type claim");
        }

        Set<String> presentedTypes = VcJsonLdTypeExpander.expandTypes(vcPayload);

        boolean matches =
                meta.getTypeValues().stream().anyMatch(requiredTypes -> presentedTypes.containsAll(requiredTypes));
        if (!matches) {
            throw new VerificationException(
                    "Presented jwt_vc_json type does not match any value in meta.type_values: " + presentedTypes);
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

    private static void validateJwtVcJsonRequestedClaims(Credential credentialQuery, JsonNode vcPayload)
            throws VerificationException {
        if (credentialQuery.getClaims() == null || credentialQuery.getClaims().isEmpty()) {
            return;
        }

        for (Claim claim : credentialQuery.getClaims()) {
            if (!ClaimPathResolver.isPresentInJson(vcPayload, claim.getPath())) {
                throw new VerificationException(
                        "Presented jwt_vc_json credential does not satisfy DCQL claim path: " + claim.getPath());
            }
        }
    }

    private static JsonNode parseJwtPayload(String jwt) throws VerificationException {
        try {
            return new JWSInput(jwt).readJsonContent(JsonNode.class);
        } catch (JWSInputException e) {
            throw new VerificationException("Could not parse presented JWT payload", e);
        }
    }

    private static JsonNode extractVcPayload(JsonNode vpJwtPayload) throws VerificationException {
        JsonNode vpEnvelope = resolveVpEnvelope(vpJwtPayload);
        JsonNode verifiableCredentials = vpEnvelope.get(VP_VERIFIABLE_CREDENTIAL_CLAIM);
        if (verifiableCredentials == null || !verifiableCredentials.isArray() || verifiableCredentials.isEmpty()) {
            throw new VerificationException(
                    "Presented jwt_vc_json Verifiable Presentation is missing verifiableCredential");
        }

        return extractVcRoot(verifiableCredentials.get(0));
    }

    private static JsonNode resolveVpEnvelope(JsonNode vpJwtPayload) {
        JsonNode vp = vpJwtPayload.get(VP_ENVELOPE_CLAIM);
        if (vp != null && vp.isObject()) {
            return vp;
        }
        return vpJwtPayload;
    }

    private static JsonNode extractVcRoot(JsonNode credentialEntry) throws VerificationException {
        if (credentialEntry.isTextual()) {
            return unwrapVcClaim(parseJwtPayload(credentialEntry.asText()));
        }
        if (credentialEntry.isObject()) {
            return unwrapVcClaim(credentialEntry);
        }

        throw new VerificationException("Unsupported verifiableCredential entry in jwt_vc_json presentation");
    }

    /** W3C VC content in jwt_vc_json is carried under the {@code vc} claim of the JWT payload. */
    private static JsonNode unwrapVcClaim(JsonNode jwtOrVcPayload) {
        JsonNode vc = jwtOrVcPayload.get(JWT_VC_CLAIM);
        if (vc != null && vc.isObject()) {
            return vc;
        }
        return jwtOrVcPayload;
    }
}
