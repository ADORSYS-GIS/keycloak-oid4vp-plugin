package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import java.util.UUID;
import org.keycloak.VCFormat;

/**
 * Constructs a DCQL query for W3C Verifiable Credentials in {@code jwt_vc_json} format.
 * Claim paths are relative to the VC root (e.g. {@code credentialSubject}), not the VP wrapper.
 */
public class JwtVcJsonCredentialConstrainer implements CredentialConstrainer<JwtVcJsonCredentialConstrainer.QuerySpec> {

    @Override
    public String format() {
        return VCFormat.JWT_VC;
    }

    @Override
    public Credential buildCredential(QuerySpec spec) {
        if (spec.typeValues() == null || spec.typeValues().isEmpty()) {
            throw new IllegalArgumentException("meta.type_values must be non-empty for jwt_vc_json credential queries");
        }

        Meta meta = new Meta();
        meta.setTypeValues(spec.typeValues());

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
        credential.setFormat(VCFormat.JWT_VC);
        credential.setMeta(meta);
        credential.setClaims(claims);
        if (spec.requireCryptographicHolderBinding() != null) {
            credential.setRequireCryptographicHolderBinding(spec.requireCryptographicHolderBinding());
        }
        return credential;
    }

    /**
     * @param typeValues allowed fully-expanded VC type sets (required, non-empty)
     * @param claimPaths claim paths relative to the VC root (e.g. {@code ["credentialSubject", "given_name"]})
     */
    public record QuerySpec(
            List<List<String>> typeValues,
            List<List<String>> claimPaths,
            Boolean requireCryptographicHolderBinding) {}
}
