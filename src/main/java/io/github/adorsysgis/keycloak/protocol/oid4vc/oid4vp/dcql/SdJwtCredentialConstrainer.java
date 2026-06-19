package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import java.util.List;
import java.util.UUID;
import org.keycloak.VCFormat;

/**
 * Constructs a DCQL query for requesting an IETF SD-JWT VC ({@code dc+sd-jwt}).
 */
public class SdJwtCredentialConstrainer implements CredentialConstrainer<SdJwtCredentialConstrainer.QuerySpec> {

    public static SdJwtCredentialConstrainer create() {
        return new SdJwtCredentialConstrainer();
    }

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public Credential buildCredential(QuerySpec spec) {
        return buildCredential(UUID.randomUUID().toString(), spec);
    }

    public Credential buildCredential(String id, QuerySpec spec) {
        if (spec.vctValues() == null || spec.vctValues().isEmpty()) {
            throw new IllegalArgumentException("meta.vct_values must be non-empty for dc+sd-jwt credential queries");
        }

        Meta meta = new Meta();
        meta.setVctValues(spec.vctValues());

        List<Claim> claims = DcqlQueryBuilder.claimsFromPaths(spec.claimPaths());

        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);
        credential.setRequireCryptographicHolderBinding(
                spec.requireCryptographicHolderBinding() != null
                        ? spec.requireCryptographicHolderBinding()
                        : Boolean.TRUE);
        return credential;
    }

    /**
     * Builds one DCQL credential query per configured authentication profile credential.
     */
    public DcqlQuery buildQuery(AuthenticationProfile profile, boolean requireCryptographicHolderBinding) {
        List<Credential> credentials = profile.getCredentials().stream()
                .map(requirement -> buildCredential(requirement, requireCryptographicHolderBinding))
                .toList();

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(
                List.of(credentials.stream().map(Credential::getId).toList()));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }

    private Credential buildCredential(CredentialRequirement requirement, boolean requireCryptographicHolderBinding) {
        return buildCredential(
                requirement.getId(),
                QuerySpec.of(
                        requirement.getCredentialTypes(), requirement.getClaims(), requireCryptographicHolderBinding));
    }

    /**
     * @param vctValues allowed vct values (required, non-empty)
     * @param claimPaths claim paths relative to the SD-JWT VC payload root
     * @param requireCryptographicHolderBinding whether KB-JWT is required; defaults to true when null
     */
    public record QuerySpec(
            List<String> vctValues, List<List<String>> claimPaths, Boolean requireCryptographicHolderBinding) {

        public static QuerySpec of(List<String> vctValues, List<String> flatClaimNames) {
            return of(vctValues, flatClaimNames, true);
        }

        public static QuerySpec of(
                List<String> vctValues, List<String> flatClaimNames, boolean requireCryptographicHolderBinding) {
            List<List<String>> paths =
                    flatClaimNames.stream().map(name -> List.of(name)).toList();
            return new QuerySpec(vctValues, paths, requireCryptographicHolderBinding);
        }
    }
}
