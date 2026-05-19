package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates the {@code vp_token} container against the issued DCQL query (OpenID4VP §8.1, §8.6).
 */
public class VpTokenStructureValidator {

    public Map<String, List<String>> validate(Map<String, List<String>> vpToken, DcqlQuery dcqlQuery)
            throws VpTokenValidationException {
        if (vpToken == null || vpToken.isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE, "vp_token is missing or empty");
        }
        if (dcqlQuery == null
                || dcqlQuery.getCredentials() == null
                || dcqlQuery.getCredentials().isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Issued authorization request is missing a DCQL query");
        }

        Set<String> expectedIds = new HashSet<>();
        for (Credential credentialQuery : dcqlQuery.getCredentials()) {
            if (credentialQuery.getId() == null || credentialQuery.getId().isBlank()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE, "DCQL credential query is missing an id");
            }
            if (!expectedIds.add(credentialQuery.getId())) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "DCQL credential query id must be unique: " + credentialQuery.getId());
            }
        }

        for (String presentedId : vpToken.keySet()) {
            if (!expectedIds.contains(presentedId)) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "vp_token contains unexpected credential query id: " + presentedId);
            }
        }

        for (Map.Entry<String, List<String>> entry : vpToken.entrySet()) {
            validatePresentationsForCredential(entry.getKey(), entry.getValue(), dcqlQuery);
        }

        if (!DcqlQueryRules.usesCredentialSets(dcqlQuery)) {
            DcqlQueryRules.requireAllCredentialQueriesPresent(
                    vpToken, dcqlQuery, VpTokenValidationException.Phase.STRUCTURE);
        } else {
            DcqlQueryRules.validateRequiredCredentialSets(
                    vpToken, dcqlQuery, VpTokenValidationException.Phase.STRUCTURE);
            DcqlQueryRules.validatePresentedCredentialsWithinCredentialSets(
                    vpToken, dcqlQuery, VpTokenValidationException.Phase.STRUCTURE);
        }

        return vpToken;
    }

    private static void validatePresentationsForCredential(
            String credentialId, List<String> presentations, DcqlQuery dcqlQuery)
            throws VpTokenValidationException {
        if (presentations == null || presentations.isEmpty()) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    "Presented vp_token map does not match DCQL credential query");
        }

        Credential credentialQuery = dcqlQuery.getCredentials().stream()
                .filter(credential -> credentialId.equals(credential.getId()))
                .findFirst()
                .orElseThrow();

        if (!credentialQuery.allowsMultiplePresentations() && presentations.size() != 1) {
            throw new VpTokenValidationException(
                    VpTokenValidationException.Phase.STRUCTURE,
                    String.format(
                            "Presented vp_token map must contain exactly one presentation for credential"
                                    + " query '%s'. Found: %d",
                            credentialQuery.getId(), presentations.size()));
        }

        for (String presentation : presentations) {
            if (presentation == null || presentation.isBlank()) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "Could not parse SD-JWT VP token contained in `vp_token`");
            }
        }
    }
}
