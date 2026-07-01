package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.keycloak.VCFormat;
import org.keycloak.utils.StringUtil;

/** Validates DCQL queries at build time per OpenID4VP 1.0 format-specific rules. */
public final class DcqlQueryValidator {

    private DcqlQueryValidator() {}

    public static void validateQuery(DcqlQuery query) {
        if (query == null
                || query.getCredentials() == null
                || query.getCredentials().isEmpty()) {
            throw new IllegalArgumentException("dcql_query.credentials must be non-empty");
        }
        query.getCredentials().forEach(DcqlQueryValidator::validateCredential);
        validateCredentialIdUniqueness(query.getCredentials());
        validateCredentialSets(query);
    }

    public static void validateCredential(Credential credential) {
        if (credential == null) {
            throw new IllegalArgumentException("dcql_query credential must not be null");
        }
        validateDcqlId(credential.getId(), "dcql_query credential id");
        if (StringUtil.isBlank(credential.getFormat())) {
            throw new IllegalArgumentException("dcql_query credential format must be non-empty");
        }

        Meta meta = credential.getMeta();
        if (meta == null) {
            throw new IllegalArgumentException(
                    "dcql_query credential meta must be present for format " + credential.getFormat());
        }

        if (!VCFormat.SD_JWT_VC.equals(credential.getFormat())) {
            throw new IllegalArgumentException("Unsupported dcql_query credential format: " + credential.getFormat());
        }
        validateSdJwtMeta(meta);

        validateClaimsAndClaimSets(credential);
        validateClaimPaths(credential);
    }

    private static void validateDcqlId(String id, String label) {
        if (StringUtil.isBlank(id)) {
            throw new IllegalArgumentException(label + " must be non-empty");
        }
        for (int i = 0; i < id.length(); i++) {
            char ch = id.charAt(i);
            if (!Character.isLetterOrDigit(ch) && ch != '_' && ch != '-') {
                throw new IllegalArgumentException(
                        label + " must consist of alphanumeric, underscore, or hyphen characters: " + id);
            }
        }
    }

    private static void validateCredentialIdUniqueness(List<Credential> credentials) {
        Set<String> seen = new HashSet<>();
        for (Credential credential : credentials) {
            if (!seen.add(credential.getId())) {
                throw new IllegalArgumentException("dcql_query credential id must be unique: " + credential.getId());
            }
        }
    }

    private static void validateClaimsAndClaimSets(Credential credential) {
        List<Claim> claims = credential.getClaims();
        List<List<String>> claimSets = credential.getClaimSets();

        if (claimSets != null && !claimSets.isEmpty()) {
            if (claims == null || claims.isEmpty()) {
                throw new IllegalArgumentException("dcql_query claim_sets must not be present when claims is absent");
            }
            validateClaimSets(credential.getId(), claims, claimSets);
        }

        if (claims == null || claims.isEmpty()) {
            return;
        }

        Set<String> claimIds = new HashSet<>();
        Set<List<String>> claimPaths = new HashSet<>();
        boolean claimSetsPresent = claimSets != null && !claimSets.isEmpty();

        for (Claim claim : claims) {
            if (claimSetsPresent) {
                validateDcqlId(claim.getId(), "dcql_query claim id");
                if (!claimIds.add(claim.getId())) {
                    throw new IllegalArgumentException("dcql_query claim id must be unique within credential "
                            + credential.getId() + ": " + claim.getId());
                }
            } else if (!StringUtil.isBlank(claim.getId())) {
                validateDcqlId(claim.getId(), "dcql_query claim id");
                if (!claimIds.add(claim.getId())) {
                    throw new IllegalArgumentException("dcql_query claim id must be unique within credential "
                            + credential.getId() + ": " + claim.getId());
                }
            }

            if (claim.getPath() != null && !claimPaths.add(claim.getPath())) {
                throw new IllegalArgumentException(
                        "dcql_query must not reference the same claim more than once in credential "
                                + credential.getId()
                                + ": "
                                + claim.getPath());
            }
        }
    }

    private static void validateClaimSets(String credentialId, List<Claim> claims, List<List<String>> claimSets) {
        Set<String> claimIds = new HashSet<>();
        for (Claim claim : claims) {
            if (!StringUtil.isBlank(claim.getId())) {
                claimIds.add(claim.getId());
            }
        }

        for (List<String> option : claimSets) {
            if (option == null || option.isEmpty()) {
                throw new IllegalArgumentException(
                        "dcql_query claim_sets option must be a non-empty array for credential " + credentialId);
            }
            for (String claimId : option) {
                if (StringUtil.isBlank(claimId)) {
                    throw new IllegalArgumentException(
                            "dcql_query claim_sets must reference non-empty claim ids for credential " + credentialId);
                }
                if (!claimIds.contains(claimId)) {
                    throw new IllegalArgumentException("dcql_query claim_sets references unknown claim id: " + claimId
                            + " in credential "
                            + credentialId);
                }
            }
        }
    }

    private static void validateSdJwtMeta(Meta meta) {
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
        for (Claim claim : credential.getClaims()) {
            List<String> path = claim.getPath();
            if (path == null || path.isEmpty()) {
                throw new IllegalArgumentException("dcql_query claim path must be non-empty");
            }
            if (path.stream().anyMatch(StringUtil::isBlank)) {
                throw new IllegalArgumentException("dcql_query claim path segments must be non-empty");
            }
            if (path.stream().anyMatch(DcqlQueryValidator::isUnsupportedPathSegment)) {
                throw new IllegalArgumentException(
                        "dcql_query claim path supports object property names only; array indexes and null wildcards are not supported");
            }
            validateClaimValues(claim.getValues());
            if (isVpWrapperPath(path)) {
                throw new IllegalArgumentException(credential.getFormat()
                        + " claim paths must be relative to the VC root, not the VP wrapper: "
                        + path);
            }
        }
    }

    private static boolean isUnsupportedPathSegment(String segment) {
        if ("null".equals(segment)) {
            return true;
        }
        return !segment.isEmpty() && segment.chars().allMatch(Character::isDigit);
    }

    private static void validateClaimValues(List<String> values) {
        if (values == null) {
            return;
        }
        if (values.isEmpty()) {
            throw new IllegalArgumentException("dcql_query claim values must be non-empty when present");
        }
        if (values.stream().anyMatch(StringUtil::isBlank)) {
            throw new IllegalArgumentException("dcql_query claim values must not contain blank entries");
        }
    }

    private static boolean isVpWrapperPath(List<String> path) {
        if (path.isEmpty()) {
            return false;
        }
        String first = path.getFirst();
        return "verifiableCredential".equals(first) || "vp".equals(first);
    }

    private static void validateCredentialSets(DcqlQuery query) {
        if (query.getCredentialSets() == null || query.getCredentialSets().isEmpty()) {
            return;
        }
        var credentialIds =
                query.getCredentials().stream().map(Credential::getId).toList();
        query.getCredentialSets().forEach(set -> {
            if (set.getOptions() == null || set.getOptions().isEmpty()) {
                throw new IllegalArgumentException("dcql_query credential_sets.options must be non-empty when present");
            }
            set.getOptions().forEach(option -> {
                if (option == null || option.isEmpty()) {
                    throw new IllegalArgumentException("dcql_query credential_sets option must be non-empty");
                }
                option.forEach(id -> {
                    if (!credentialIds.contains(id)) {
                        throw new IllegalArgumentException(
                                "dcql_query credential_sets references unknown credential id: " + id);
                    }
                });
            });
        });
    }
}
