package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Validates returned {@code vp_token} presentations against the issued DCQL query (OpenID4VP §6.4, §8.6).
 *
 * <p>Integrity and authenticity checks remain in {@link
 * io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator}; this validator
 * verifies DCQL satisfaction on the verifier side.
 */
public class VpTokenDcqlValidator {

    private final DcqlSatisfactionValidator dcqlSatisfactionValidator = new DcqlSatisfactionValidator();

    public List<PresentedCredential> validate(Map<String, List<String>> vpToken, DcqlQuery dcqlQuery)
            throws VpTokenValidationException {
        if (vpToken == null || vpToken.isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE, "vp_token is missing or empty");
        }
        if (dcqlQuery == null
                || dcqlQuery.getCredentials() == null
                || dcqlQuery.getCredentials().isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE, "Issued authorization request is missing a DCQL query");
        }

        Map<String, Credential> credentialsById = new HashMap<>();
        for (Credential credentialQuery : dcqlQuery.getCredentials()) {
            if (credentialQuery.getId() == null || credentialQuery.getId().isBlank()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE, "DCQL credential query is missing an id");
            }
            credentialsById.put(credentialQuery.getId(), credentialQuery);
        }

        List<PresentedCredential> presentations = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : vpToken.entrySet()) {
            Credential credentialQuery = credentialsById.get(entry.getKey());
            if (credentialQuery == null) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "vp_token contains unexpected credential query id: " + entry.getKey());
            }

            List<String> encodedPresentations = entry.getValue();
            if (encodedPresentations == null || encodedPresentations.isEmpty()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "Presented vp_token map does not match DCQL credential query");
            }

            for (String encodedPresentation : encodedPresentations) {
                presentations.add(parsePresentation(entry.getKey(), credentialQuery, encodedPresentation));
            }
        }

        for (PresentedCredential presented : presentations) {
            validateHolderBinding(presented);
        }

        dcqlSatisfactionValidator.validate(presentations, dcqlQuery);
        return presentations;
    }

    private static void validateHolderBinding(PresentedCredential presented) throws VpTokenValidationException {
        Credential credentialQuery = presented.credentialQuery();
        Boolean required = credentialQuery.getRequireCryptographicHolderBinding();
        if (!Boolean.FALSE.equals(required)
                && presented.presentation().getKeyBindingJWT().isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.DCQL,
                    "DCQL query requires cryptographic holder binding (Key Binding JWT)");
        }
    }

    private static PresentedCredential parsePresentation(
            String credentialQueryId, Credential credentialQuery, String encodedPresentation)
            throws VpTokenValidationException {
        if (encodedPresentation == null || encodedPresentation.isBlank()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Could not parse SD-JWT VP token contained in `vp_token`");
        }

        try {
            String normalizedPresentation = VpTokenPresentationDecoder.decodeIfBase64Url(encodedPresentation);
            SdJwtVP presentation = SdJwtVP.of(normalizedPresentation);
            return new PresentedCredential(credentialQueryId, credentialQuery, normalizedPresentation, presentation);
        } catch (RuntimeException e) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Could not parse SD-JWT VP token contained in `vp_token`",
                    e);
        }
    }
}
