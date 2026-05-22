package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import java.util.UUID;
import org.keycloak.VCFormat;

/**
 * Constructs a DCQL query for requesting an IETF SD-JWT VC ({@code dc+sd-jwt}).
 */
public class SdJwtCredentialConstrainer implements CredentialConstrainer<SdJwtCredentialConstrainer.QuerySpec> {

    @Override
    public String format() {
        return VCFormat.SD_JWT_VC;
    }

    @Override
    public Credential buildCredential(QuerySpec spec) {
        if (spec.vctValues() == null || spec.vctValues().isEmpty()) {
            throw new IllegalArgumentException("meta.vct_values must be non-empty for dc+sd-jwt credential queries");
        }

        Meta meta = new Meta();
        meta.setVctValues(spec.vctValues());

        List<Claim> claims = spec.claimPaths().stream()
                .map(path -> {
                    Claim claim = new Claim();
                    claim.setId(UUID.randomUUID().toString());
                    claim.setPath(path);
                    return claim;
                })
                .toList();

        Credential credential = new Credential();
        credential.setId(UUID.randomUUID().toString());
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
     * @param vctValues allowed vct values (required, non-empty)
     * @param claimPaths claim paths relative to the SD-JWT VC payload root
     * @param requireCryptographicHolderBinding whether KB-JWT is required; defaults to true when null
     */
    public record QuerySpec(
            List<String> vctValues, List<List<String>> claimPaths, Boolean requireCryptographicHolderBinding) {

        public static QuerySpec of(List<String> vctValues, List<String> flatClaimNames) {
            List<List<String>> paths =
                    flatClaimNames.stream().map(name -> List.of(name)).toList();
            return new QuerySpec(vctValues, paths, true);
        }
    }
}
