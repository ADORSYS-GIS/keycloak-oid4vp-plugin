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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.keycloak.VCFormat;
import org.keycloak.utils.StringUtil;

/**
 * Builds a DCQL query from an {@link AuthenticationProfile}.
 *
 * <p>Each {@link CredentialRequirement} becomes one DCQL credential query. All credentials
 * are required and grouped into a single {@link CredentialSet}. Format dispatch is local:
 * {@code mso_mdoc} builds an mDoc credential, everything else falls back to SD-JWT VC.
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

        // All credentials are required → one CredentialSet with a single option listing all ids.
        List<String> allIds = credentials.stream().map(Credential::getId).toList();
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setRequired(true);
        credentialSet.setOptions(List.of(allIds));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(List.of(credentialSet));
        return query;
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
        CredentialFormat format = CredentialFormat.fromIdentifier(requirement.getFormat());
        return switch (format) {
            case MSO_MDOC -> buildMdocCredential(requirement, requireHolderBinding);
            case SD_JWT_VC -> buildSdJwtCredential(requirement, requireHolderBinding);
        };
    }

    private Credential buildSdJwtCredential(CredentialRequirement requirement, boolean requireHolderBinding) {
        Credential credential = new Credential();
        credential.setId(requirement.getId());
        credential.setFormat(VCFormat.SD_JWT_VC);
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
        credential.setFormat(CredentialFormat.MSO_MDOC.getIdentifier());
        Meta meta = new Meta();
        List<String> types = requirement.getCredentialTypes();
        meta.setDoctypeValue(types == null || types.isEmpty() ? null : types.getFirst());
        credential.setMeta(meta);
        credential.setClaims(requirement.getClaimReferences().stream()
                .map(DcqlQueryGenerator::mdocClaim)
                .toList());
        credential.setRequireCryptographicHolderBinding(requireHolderBinding);
        return credential;
    }

    private static List<Claim> claimsFromNames(List<String> names) {
        if (names == null || names.isEmpty()) {
            return List.of();
        }
        List<Claim> claims = new ArrayList<>(names.size());
        int index = 0;
        for (String name : names) {
            if (StringUtil.isBlank(name)) {
                continue;
            }
            Claim claim = new Claim();
            claim.setId("claim_" + index++);
            claim.setPath(List.of(name));
            claims.add(claim);
        }
        return claims;
    }

    private static Claim mdocClaim(ClaimReference ref) {
        if (!ref.isNamespaced()) {
            throw new IllegalArgumentException(
                    String.format("mDoc claims must be namespaced (\"namespace/name\"), got: %s", ref.name()));
        }

        Claim claim = new Claim();
        claim.setId(UUID.randomUUID().toString());
        claim.setPath(List.of(ref.namespace(), ref.name()));
        return claim;
    }
}
