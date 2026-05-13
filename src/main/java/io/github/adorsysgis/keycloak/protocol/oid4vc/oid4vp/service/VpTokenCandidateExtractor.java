package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.keycloak.VCFormat;
import org.keycloak.utils.StringUtil;

/**
 * Extracts SD-JWT VP presentation candidates from final-spec vp_token maps.
 */
public class VpTokenCandidateExtractor {

    public List<String> extractSdJwtCandidates(DcqlQuery dcqlQuery, Map<String, List<String>> vpToken) {
        Map<String, Credential> credentialsById = credentialsById(dcqlQuery);
        if (vpToken == null || vpToken.isEmpty()) {
            throw invalid("vp_token must be a non-empty JSON object keyed by DCQL credential query IDs");
        }

        validateKnownCredentialQueryIds(vpToken.keySet(), credentialsById);
        validatePresentationArrays(vpToken, credentialsById);
        validateRequiredCredentialSets(dcqlQuery, vpToken.keySet(), credentialsById);

        List<String> candidates = new ArrayList<>();
        vpToken.forEach((queryId, presentations) -> {
            Credential credential = credentialsById.get(queryId);
            if (VCFormat.SD_JWT_VC.equals(credential.getFormat())) {
                candidates.addAll(presentations);
            }
        });

        if (candidates.isEmpty()) {
            throw invalid("Presented vp_token map does not contain any SD-JWT VP presentations");
        }

        return List.copyOf(candidates);
    }

    private Map<String, Credential> credentialsById(DcqlQuery dcqlQuery) {
        if (dcqlQuery == null
                || dcqlQuery.getCredentials() == null
                || dcqlQuery.getCredentials().isEmpty()) {
            throw new IllegalStateException("Invalid DCQL query in authorization context. Expected credentials.");
        }

        Map<String, Credential> credentialsById = new LinkedHashMap<>();
        for (Credential credential : dcqlQuery.getCredentials()) {
            String id = credential.getId();
            if (StringUtil.isBlank(id)) {
                throw new IllegalStateException("Invalid DCQL query in authorization context. Credential ID is blank.");
            }
            if (credentialsById.put(id, credential) != null) {
                throw new IllegalStateException(
                        "Invalid DCQL query in authorization context. Duplicate credential ID: " + id);
            }
        }
        return Map.copyOf(credentialsById);
    }

    private void validateKnownCredentialQueryIds(
            Set<String> returnedQueryIds, Map<String, Credential> credentialsById) {
        Set<String> unknownQueryIds = new LinkedHashSet<>(returnedQueryIds);
        unknownQueryIds.removeAll(credentialsById.keySet());
        if (!unknownQueryIds.isEmpty()) {
            throw invalid("Presented vp_token map contains unknown DCQL credential query IDs: " + unknownQueryIds);
        }
    }

    private void validatePresentationArrays(
            Map<String, List<String>> vpToken, Map<String, Credential> credentialsById) {
        vpToken.forEach((queryId, presentations) -> {
            if (presentations == null || presentations.isEmpty()) {
                throw invalid("vp_token entry `%s` must contain at least one presentation".formatted(queryId));
            }

            Credential credential = credentialsById.get(queryId);
            if (!Boolean.TRUE.equals(credential.getMultiple()) && presentations.size() > 1) {
                throw invalid("DCQL credential query `%s` does not allow multiple presentations".formatted(queryId));
            }

            if (presentations.stream().anyMatch(StringUtil::isBlank)) {
                throw invalid("vp_token entry `%s` must contain non-blank presentation strings".formatted(queryId));
            }
        });
    }

    private void validateRequiredCredentialSets(
            DcqlQuery dcqlQuery, Set<String> returnedQueryIds, Map<String, Credential> credentialsById) {
        List<CredentialSet> credentialSets = dcqlQuery.getCredentialSets();
        if (credentialSets == null || credentialSets.isEmpty()) {
            Set<String> missingQueryIds = new LinkedHashSet<>(credentialsById.keySet());
            missingQueryIds.removeAll(returnedQueryIds);
            if (!missingQueryIds.isEmpty()) {
                throw invalid(
                        "Presented vp_token map is missing required DCQL credential query IDs: " + missingQueryIds);
            }
            return;
        }

        for (CredentialSet credentialSet : credentialSets) {
            if (!Boolean.FALSE.equals(credentialSet.getRequired())
                    && !isCredentialSetSatisfied(credentialSet, returnedQueryIds, credentialsById)) {
                throw invalid("Presented vp_token map does not satisfy a required DCQL credential set");
            }
        }
    }

    private boolean isCredentialSetSatisfied(
            CredentialSet credentialSet, Set<String> returnedQueryIds, Map<String, Credential> credentialsById) {
        List<List<String>> options = credentialSet.getOptions();
        if (options == null || options.isEmpty()) {
            throw new IllegalStateException(
                    "Invalid DCQL query in authorization context. Credential set has no options.");
        }

        return options.stream().anyMatch(option -> {
            validateOption(option, credentialsById);
            return returnedQueryIds.containsAll(option);
        });
    }

    private void validateOption(List<String> option, Map<String, Credential> credentialsById) {
        if (option == null || option.isEmpty()) {
            throw new IllegalStateException(
                    "Invalid DCQL query in authorization context. Credential set contains an empty option.");
        }

        Set<String> unknownOptionIds = new LinkedHashSet<>(option);
        unknownOptionIds.removeAll(credentialsById.keySet());
        if (!unknownOptionIds.isEmpty()) {
            throw new IllegalStateException(
                    "Invalid DCQL query in authorization context. Credential set references unknown credential IDs: "
                            + unknownOptionIds);
        }
    }

    private InvalidVpTokenException invalid(String message) {
        return new InvalidVpTokenException(message);
    }

    public static class InvalidVpTokenException extends IllegalArgumentException {

        public InvalidVpTokenException(String message) {
            super(message);
        }
    }
}
