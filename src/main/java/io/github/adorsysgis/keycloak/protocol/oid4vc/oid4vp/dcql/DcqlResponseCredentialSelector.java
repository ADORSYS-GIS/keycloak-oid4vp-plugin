package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Validates that the credential IDs returned in a vp_token satisfy the signed DCQL query.
 */
public final class DcqlResponseCredentialSelector {

    private DcqlResponseCredentialSelector() {}

    public static Set<String> selectPresentedCredentialIds(DcqlQuery dcqlQuery, Set<String> presentedCredentialIds) {
        Set<String> credentialQueryIds = credentialQueryIds(dcqlQuery);
        Set<String> unknownCredentialIds = new HashSet<>(presentedCredentialIds);
        unknownCredentialIds.removeAll(credentialQueryIds);
        if (!unknownCredentialIds.isEmpty()) {
            throw new IllegalArgumentException(
                    "Presented vp_token map contains unknown credential(s): " + unknownCredentialIds);
        }

        List<CredentialSet> credentialSets = effectiveCredentialSets(dcqlQuery);
        if (!matchesCredentialSets(
                credentialSets, credentialQueryIds, presentedCredentialIds, 0, new LinkedHashSet<>())) {
            throw new IllegalArgumentException("Presented vp_token map does not satisfy DCQL credential_sets");
        }

        return Set.copyOf(presentedCredentialIds);
    }

    private static Set<String> credentialQueryIds(DcqlQuery dcqlQuery) {
        if (dcqlQuery == null
                || dcqlQuery.getCredentials() == null
                || dcqlQuery.getCredentials().isEmpty()) {
            throw new IllegalArgumentException("DCQL query must contain at least one credential query");
        }
        return dcqlQuery.getCredentials().stream().map(Credential::getId).collect(java.util.stream.Collectors.toSet());
    }

    private static List<CredentialSet> effectiveCredentialSets(DcqlQuery dcqlQuery) {
        if (dcqlQuery.getCredentialSets() != null
                && !dcqlQuery.getCredentialSets().isEmpty()) {
            return dcqlQuery.getCredentialSets();
        }

        CredentialSet allCredentials = new CredentialSet();
        allCredentials.setRequired(Boolean.TRUE);
        allCredentials.setOptions(List.of(
                dcqlQuery.getCredentials().stream().map(Credential::getId).toList()));
        return List.of(allCredentials);
    }

    private static boolean matchesCredentialSets(
            List<CredentialSet> credentialSets,
            Set<String> credentialQueryIds,
            Set<String> presentedCredentialIds,
            int index,
            Set<String> coveredCredentialIds) {
        if (index == credentialSets.size()) {
            return coveredCredentialIds.equals(presentedCredentialIds);
        }

        CredentialSet credentialSet = credentialSets.get(index);
        if (!isRequired(credentialSet)
                && matchesCredentialSets(
                        credentialSets, credentialQueryIds, presentedCredentialIds, index + 1, coveredCredentialIds)) {
            return true;
        }

        List<List<String>> options = credentialSet.getOptions();
        if (options == null || options.isEmpty()) {
            throw new IllegalArgumentException("DCQL credential_set options must be non-empty");
        }

        for (List<String> option : options) {
            Set<String> optionIds = optionIds(credentialSet, option, credentialQueryIds);
            if (!presentedCredentialIds.containsAll(optionIds)) {
                continue;
            }

            Set<String> nextCoveredCredentialIds = new LinkedHashSet<>(coveredCredentialIds);
            nextCoveredCredentialIds.addAll(optionIds);
            if (matchesCredentialSets(
                    credentialSets, credentialQueryIds, presentedCredentialIds, index + 1, nextCoveredCredentialIds)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isRequired(CredentialSet credentialSet) {
        return !Boolean.FALSE.equals(credentialSet.getRequired());
    }

    private static Set<String> optionIds(
            CredentialSet credentialSet, List<String> option, Set<String> credentialQueryIds) {
        if (option == null || option.isEmpty()) {
            throw new IllegalArgumentException("DCQL credential_set options must be non-empty");
        }

        Set<String> optionIds = new LinkedHashSet<>(option);
        if (!credentialQueryIds.containsAll(optionIds)) {
            throw new IllegalArgumentException("DCQL credential_set references unknown credential query id");
        }
        return optionIds;
    }
}
