package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirementGroup;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.keycloak.utils.StringUtil;

/**
 * Builds a DCQL query from an {@link AuthenticationProfile}.
 *
 * <p>Each {@link CredentialRequirement} becomes one DCQL credential query. The profile's
 * credential groups become DCQL credential sets. Profiles without explicit groups keep the
 * legacy behavior where all configured credentials are required together.
 */
public final class DcqlQueryGenerator {

    public static DcqlQueryGenerator create() {
        return new DcqlQueryGenerator();
    }

    public DcqlQuery buildQuery(AuthenticationProfile profile, boolean requireCryptographicHolderBinding) {
        List<Credential> credentials = new ArrayList<>();

        for (CredentialRequirement requirement : profile.getCredentials()) {
            credentials.add(buildCredential(requirement, requireCryptographicHolderBinding));
        }

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(profile.getEffectiveCredentialGroups().stream()
                .map(DcqlQueryGenerator::buildCredentialSet)
                .toList());
        return query;
    }

    private static CredentialSet buildCredentialSet(CredentialRequirementGroup group) {
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setRequired(group.isRequired());
        credentialSet.setOptions(group.getOptions());
        return credentialSet;
    }

    /** Wraps a single credential into a DcqlQuery with its own credential_set, for validators. */
    public static DcqlQuery singleCredentialQuery(Credential credential) {
        CredentialSet set = new CredentialSet();
        set.setRequired(true);
        set.setOptions(List.of(List.of(credential.getId())));
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        query.setCredentialSets(List.of(set));
        return query;
    }

    private Credential buildCredential(CredentialRequirement requirement, boolean requireHolderBinding) {
        CredentialFormat format = CredentialFormat.fromValue(requirement.getFormat());
        return switch (format) {
            case MSO_MDOC -> buildMdocCredential(requirement, requireHolderBinding);
            case SD_JWT_VC -> buildSdJwtCredential(requirement, requireHolderBinding);
        };
    }

    private Credential buildSdJwtCredential(CredentialRequirement requirement, boolean requireHolderBinding) {
        Credential credential = new Credential();
        credential.setId(requirement.getId());
        credential.setFormat(CredentialFormat.SD_JWT_VC.getValue());
        Meta meta = new Meta();
        meta.setVctValues(requirement.getCredentialTypes());
        credential.setMeta(meta);
        credential.setClaims(claimsFromNames(requirement.getClaims()));
        credential.setRequireCryptographicHolderBinding(requireHolderBinding);
        return credential;
    }

    private Credential buildMdocCredential(CredentialRequirement requirement, boolean requireHolderBinding) {
        Credential credential = new Credential();
        credential.setId(requirement.getId());
        credential.setFormat(CredentialFormat.MSO_MDOC.getValue());
        Meta meta = new Meta();
        meta.setDoctypeValue(requirement.getCredentialTypes().getFirst());
        credential.setMeta(meta);
        credential.setClaims(requirement.getClaimReferences().stream()
                .map(DcqlQueryGenerator::buildClaim)
                .toList());
        credential.setRequireCryptographicHolderBinding(requireHolderBinding);
        return credential;
    }

    private static List<Claim> claimsFromNames(List<String> names) {
        if (names == null || names.isEmpty()) {
            return List.of();
        }

        return names.stream()
                .filter(name -> !StringUtil.isBlank(name))
                .map(ClaimReference::parse)
                .map(DcqlQueryGenerator::buildClaim)
                .toList();
    }

    private static Claim buildClaim(ClaimReference ref) {
        Claim claim = new Claim();
        claim.setId(UUID.randomUUID().toString());
        claim.setPath(ref.isNamespaced() ? List.of(ref.namespace(), ref.name()) : List.of(ref.name()));
        return claim;
    }
}
