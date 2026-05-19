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
 *
 * @author <a href="mailto:Bertrand.Ogen@adorsys.com">Bertrand Ogen</a>
 * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-parameters">
 * Response</a>
 */
public class VpTokenCandidateExtractor {

    /**
     * Validates the final-spec vp_token map against the stored DCQL query and returns the SD-JWT presentations
     * that can be forwarded to the SD-JWT authenticator.
     */
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
            // This authenticator currently handles SD-JWT VCs only; other formats are left out deliberately.
            if (VCFormat.SD_JWT_VC.equals(credential.getFormat())) {
                candidates.addAll(extractSdJwtStrings(queryId, presentations));
            }
        });

        if (candidates.isEmpty()) {
            throw invalid("No supported format presentations found in vp_token");
        }

        return List.copyOf(candidates);
    }

    /**
     * The current login authenticator stores one SD-JWT VP in one auth note, so this flow rejects multiple
     * SD-JWT candidates instead of silently choosing one.
     */
    public String extractSingleSdJwtCandidate(DcqlQuery dcqlQuery, Map<String, List<String>> vpToken) {
        List<String> candidates = extractSdJwtCandidates(dcqlQuery, vpToken);
        if (candidates.size() != 1) {
            throw invalid("OpenID4VP login supports exactly one SD-JWT VP candidate. Found: " + candidates.size());
        }

        return candidates.getFirst();
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
            // Each vp_token entry is an array of presentations for the matching DCQL credential query id.
            if (presentations == null || presentations.isEmpty()) {
                throw invalid("vp_token entry `%s` must contain at least one presentation".formatted(queryId));
            }

            Credential credential = credentialsById.get(queryId);
            // Per DCQL, omitted `multiple` means the verifier requested at most one presentation.
            if (!Boolean.TRUE.equals(credential.getMultiple()) && presentations.size() > 1) {
                throw invalid("DCQL credential query `%s` does not allow multiple presentations".formatted(queryId));
            }
        });
    }

    private List<String> extractSdJwtStrings(String queryId, List<String> presentations) {
        List<String> sdJwtPresentations = new ArrayList<>();
        for (String presentationString : presentations) {
            if (StringUtil.isBlank(presentationString)) {
                throw invalid("vp_token entry `%s` must contain non-blank presentation strings for SD-JWT"
                        .formatted(queryId));
            }
            sdJwtPresentations.add(presentationString);
        }
        return sdJwtPresentations;
    }

    private void validateRequiredCredentialSets(
            DcqlQuery dcqlQuery, Set<String> returnedQueryIds, Map<String, Credential> credentialsById) {
        List<CredentialSet> credentialSets = dcqlQuery.getCredentialSets();
        if (credentialSets == null || credentialSets.isEmpty()) {
            // Without credential_sets, every credential query in the DCQL request is mandatory.
            Set<String> missingQueryIds = new LinkedHashSet<>(credentialsById.keySet());
            missingQueryIds.removeAll(returnedQueryIds);
            if (!missingQueryIds.isEmpty()) {
                throw invalid(
                        "Presented vp_token map is missing required DCQL credential query IDs: " + missingQueryIds);
            }
            return;
        }

        for (CredentialSet credentialSet : credentialSets) {
            // A credential set is required unless it explicitly declares required=false.
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

        // A credential set option is satisfied only when all credential query IDs in that option are present.
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
