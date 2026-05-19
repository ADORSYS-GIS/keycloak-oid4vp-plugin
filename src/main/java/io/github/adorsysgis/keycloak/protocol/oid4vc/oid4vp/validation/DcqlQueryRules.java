package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Shared DCQL selection rules (OpenID4VP §6.4.2, §8.1).
 */
final class DcqlQueryRules {

    private DcqlQueryRules() {}

    static boolean usesCredentialSets(DcqlQuery dcqlQuery) {
        return dcqlQuery.getCredentialSets() != null && !dcqlQuery.getCredentialSets().isEmpty();
    }

    static Set<String> credentialQueryIds(DcqlQuery dcqlQuery) {
        return dcqlQuery.getCredentials().stream()
                .map(credential -> credential.getId())
                .collect(Collectors.toSet());
    }

    static void requireAllCredentialQueriesPresent(
            Map<String, ?> presentedById, DcqlQuery dcqlQuery, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        for (String credentialId : credentialQueryIds(dcqlQuery)) {
            if (!presentedById.containsKey(credentialId)) {
                throw new VpTokenValidationException(
                        phase, "Presented vp_token map does not match DCQL credential query");
            }
        }
    }

    static void validateRequiredCredentialSets(
            Map<String, ?> presentedById, DcqlQuery dcqlQuery, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        if (!usesCredentialSets(dcqlQuery)) {
            return;
        }

        for (CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
            boolean required = credentialSet.getRequired() == null || credentialSet.getRequired();
            if (!required) {
                continue;
            }
            if (credentialSet.getOptions() == null || credentialSet.getOptions().isEmpty()) {
                throw new VpTokenValidationException(phase, "DCQL credential_sets entry is missing options");
            }
            if (!satisfiesAnyCredentialSetOption(presentedById, credentialSet.getOptions())) {
                throw new VpTokenValidationException(
                        phase,
                        "Returned presentations do not satisfy required DCQL credential_sets constraints");
            }
        }
    }

    /**
     * When {@code credential_sets} is used, every returned credential id must belong to a satisfied
     * credential set option (§8.1 — no entries for non-matching optional queries).
     */
    static void validatePresentedCredentialsWithinCredentialSets(
            Map<String, ?> presentedById, DcqlQuery dcqlQuery, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        if (!usesCredentialSets(dcqlQuery)) {
            return;
        }

        Set<String> permittedIds = permittedCredentialIds(presentedById, dcqlQuery);
        for (String presentedId : presentedById.keySet()) {
            if (!permittedIds.contains(presentedId)) {
                throw new VpTokenValidationException(
                        phase,
                        "vp_token contains credential query id outside satisfied DCQL credential_sets: "
                                + presentedId);
            }
        }
    }

    private static Set<String> permittedCredentialIds(Map<String, ?> presentedById, DcqlQuery dcqlQuery) {
        Set<String> permitted = new HashSet<>();
        for (CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
            List<List<String>> options = credentialSet.getOptions();
            if (options == null) {
                continue;
            }
            for (List<String> option : options) {
                if (option == null || option.isEmpty()) {
                    continue;
                }
                if (presentedById.keySet().containsAll(option)) {
                    permitted.addAll(option);
                }
            }
        }
        return permitted;
    }

    private static boolean satisfiesAnyCredentialSetOption(Map<String, ?> presentedById, List<List<String>> options) {
        for (List<String> option : options) {
            if (option == null || option.isEmpty()) {
                continue;
            }
            if (presentedById.keySet().containsAll(option)) {
                return true;
            }
        }
        return false;
    }
}
