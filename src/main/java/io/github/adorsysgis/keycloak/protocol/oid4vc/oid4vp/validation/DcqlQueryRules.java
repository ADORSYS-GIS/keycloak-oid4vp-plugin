package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.HashMap;
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
        return dcqlQuery.getCredentialSets() != null
                && !dcqlQuery.getCredentialSets().isEmpty();
    }

    static Set<String> credentialQueryIds(DcqlQuery dcqlQuery) {
        return dcqlQuery.getCredentials().stream()
                .map(credential -> credential.getId())
                .collect(Collectors.toSet());
    }

    /**
     * Validates {@code vp_token} key set and per-id presentation counts (OpenID4VP §8.1) before reducing
     * presentations to a map.
     */
    static void validateVpTokenStructure(
            List<PresentedCredential> presentations, DcqlQuery dcqlQuery, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        Map<String, Credential> credentialsById = credentialsById(dcqlQuery);
        Map<String, Integer> presentationCounts = countPresentationsById(presentations, credentialsById, phase);
        validatePresentationCounts(presentationCounts, credentialsById, phase);

        if (!usesCredentialSets(dcqlQuery)) {
            if (!presentationCounts.keySet().equals(credentialsById.keySet())) {
                throw new VpTokenValidationException(
                        phase, "Presented vp_token map does not match DCQL credential query");
            }
        }
    }

    private static Map<String, Credential> credentialsById(DcqlQuery dcqlQuery) {
        Map<String, Credential> credentialsById = new HashMap<>();
        for (Credential credential : dcqlQuery.getCredentials()) {
            credentialsById.put(credential.getId(), credential);
        }
        return credentialsById;
    }

    private static Map<String, Integer> countPresentationsById(
            List<PresentedCredential> presentations,
            Map<String, Credential> credentialsById,
            VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        Map<String, Integer> presentationCounts = new HashMap<>();
        for (PresentedCredential presented : presentations) {
            String credentialId = presented.credentialQueryId();
            if (!credentialsById.containsKey(credentialId)) {
                throw new VpTokenValidationException(
                        phase, "vp_token contains unknown DCQL credential query id: " + credentialId);
            }
            presentationCounts.merge(credentialId, 1, Integer::sum);
        }
        return presentationCounts;
    }

    private static void validatePresentationCounts(
            Map<String, Integer> presentationCounts,
            Map<String, Credential> credentialsById,
            VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        for (Map.Entry<String, Integer> entry : presentationCounts.entrySet()) {
            Credential credentialQuery = credentialsById.get(entry.getKey());
            if (!credentialQuery.allowsMultiplePresentations() && entry.getValue() != 1) {
                throw new VpTokenValidationException(
                        phase,
                        "vp_token must contain exactly one presentation for DCQL credential query id: "
                                + entry.getKey());
            }
        }
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
                        phase, "Returned presentations do not satisfy required DCQL credential_sets constraints");
            }
        }
    }

    /**
     * When {@code credential_sets} is used, each set must be satisfied by exactly one of its {@code options}
     * (OpenID4VP §6.4.2). Returned credential ids must match the union of those selected options and must not
     * combine ids from multiple alternatives within the same credential set.
     */
    static void validatePresentedCredentialsWithinCredentialSets(
            Map<String, ?> presentedById, DcqlQuery dcqlQuery, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        if (!usesCredentialSets(dcqlQuery)) {
            return;
        }

        Set<String> presentedIds = presentedById.keySet();
        Set<String> selectedCredentialIds = new HashSet<>();
        for (CredentialSet credentialSet : dcqlQuery.getCredentialSets()) {
            Set<String> selectedOption = selectedCredentialSetOption(presentedIds, credentialSet, phase);
            if (selectedOption != null) {
                selectedCredentialIds.addAll(selectedOption);
            }
        }

        if (!selectedCredentialIds.equals(presentedIds)) {
            throw new VpTokenValidationException(
                    phase,
                    "vp_token contains credential query id outside satisfied DCQL credential_sets: "
                            + firstUnexpectedId(presentedIds, selectedCredentialIds));
        }
    }

    private static String firstUnexpectedId(Set<String> presentedIds, Set<String> selectedCredentialIds) {
        return presentedIds.stream()
                .filter(id -> !selectedCredentialIds.contains(id))
                .findFirst()
                .orElse(presentedIds.stream().findFirst().orElse("unknown"));
    }

    /**
     * @return ids of the single satisfied option for this credential set, or {@code null} when no credential
     *     from the set was returned
     */
    private static Set<String> selectedCredentialSetOption(
            Set<String> presentedIds, CredentialSet credentialSet, VpTokenValidationException.Phase phase)
            throws VpTokenValidationException {
        List<List<String>> options = credentialSet.getOptions();
        if (options == null || options.isEmpty()) {
            return null;
        }

        Set<String> credentialIdsInSet = options.stream()
                .filter(option -> option != null && !option.isEmpty())
                .flatMap(option -> option.stream())
                .collect(Collectors.toSet());

        Set<String> presentedFromSet = new HashSet<>(presentedIds);
        presentedFromSet.retainAll(credentialIdsInSet);
        if (presentedFromSet.isEmpty()) {
            return null;
        }

        List<Set<String>> matchingOptions = options.stream()
                .filter(option -> option != null && !option.isEmpty())
                .map(option -> Set.copyOf(option))
                .filter(option -> option.equals(presentedFromSet))
                .toList();

        if (matchingOptions.size() == 1) {
            return matchingOptions.getFirst();
        }

        throw new VpTokenValidationException(
                phase,
                "vp_token must satisfy exactly one DCQL credential_sets option, but presented ids were: "
                        + presentedFromSet);
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
