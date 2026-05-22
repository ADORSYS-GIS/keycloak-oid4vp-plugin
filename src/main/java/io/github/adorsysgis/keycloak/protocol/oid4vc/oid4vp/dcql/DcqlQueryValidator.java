package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import org.keycloak.VCFormat;
import org.keycloak.utils.StringUtil;

/**
 * Validates DCQL queries at build time per OpenID4VP 1.0 format-specific rules.
 */
public final class DcqlQueryValidator {

    private DcqlQueryValidator() {}

    public static void validateQuery(DcqlQuery query) {
        if (query == null || query.getCredentials() == null || query.getCredentials().isEmpty()) {
            throw new IllegalArgumentException("dcql_query.credentials must be non-empty");
        }
        query.getCredentials().forEach(DcqlQueryValidator::validateCredential);
        validateCredentialSets(query);
    }

    public static void validateCredential(Credential credential) {
        if (credential == null) {
            throw new IllegalArgumentException("dcql_query credential must not be null");
        }
        if (StringUtil.isBlank(credential.getId())) {
            throw new IllegalArgumentException("dcql_query credential id must be non-empty");
        }
        if (StringUtil.isBlank(credential.getFormat())) {
            throw new IllegalArgumentException("dcql_query credential format must be non-empty");
        }

        Meta meta = credential.getMeta();
        if (meta == null) {
            throw new IllegalArgumentException(
                    "dcql_query credential meta must be present for format " + credential.getFormat());
        }

        switch (credential.getFormat()) {
            case VCFormat.SD_JWT_VC -> validateSdJwtMeta(meta);
            case VCFormat.JWT_VC -> validateJwtVcJsonMeta(meta);
            default ->
                throw new IllegalArgumentException("Unsupported dcql_query credential format: " + credential.getFormat());
        }

        validateClaimPaths(credential);
    }

    private static void validateSdJwtMeta(Meta meta) {
        if (meta.getVctValues() == null || meta.getVctValues().isEmpty()) {
            throw new IllegalArgumentException("meta.vct_values must be non-empty for dc+sd-jwt credential queries");
        }
        if (meta.getVctValues().stream().anyMatch(StringUtil::isBlank)) {
            throw new IllegalArgumentException("meta.vct_values must not contain blank entries");
        }
    }

    private static void validateJwtVcJsonMeta(Meta meta) {
        if (meta.getTypeValues() == null || meta.getTypeValues().isEmpty()) {
            throw new IllegalArgumentException("meta.type_values must be non-empty for jwt_vc_json credential queries");
        }
        for (List<String> typeSet : meta.getTypeValues()) {
            if (typeSet == null || typeSet.isEmpty()) {
                throw new IllegalArgumentException("meta.type_values entries must be non-empty arrays");
            }
            if (typeSet.stream().anyMatch(StringUtil::isBlank)) {
                throw new IllegalArgumentException("meta.type_values must not contain blank type strings");
            }
        }
    }

    private static void validateClaimPaths(Credential credential) {
        if (credential.getClaims() == null) {
            return;
        }
        for (Claim claim : credential.getClaims()) {
            if (claim.getPath() == null || claim.getPath().isEmpty()) {
                throw new IllegalArgumentException("dcql_query claim path must be non-empty");
            }
            if (claim.getPath().stream().anyMatch(StringUtil::isBlank)) {
                throw new IllegalArgumentException("dcql_query claim path segments must be non-empty");
            }
            if (isVpWrapperPath(claim.getPath())) {
                throw new IllegalArgumentException(
                        credential.getFormat()
                                + " claim paths must be relative to the VC root, not the VP wrapper: "
                                + claim.getPath());
            }
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
