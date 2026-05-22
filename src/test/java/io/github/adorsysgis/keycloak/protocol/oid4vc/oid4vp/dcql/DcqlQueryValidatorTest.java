package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class DcqlQueryValidatorTest {

    @Test
    void rejectsEmptyVctValuesForSdJwt() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of());
        credential.setMeta(meta);

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsVpWrapperPathsForSdJwt() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("vp", "sub"));
        credential.setClaims(List.of(claim));

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsVpWrapperPathsForJwtVcJson() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.JWT_VC);
        Meta meta = new Meta();
        meta.setTypeValues(List.of(List.of("VerifiableCredential", "IDCredential")));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("verifiableCredential", "credentialSubject", "given_name"));
        credential.setClaims(List.of(claim));

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void acceptsValidSdJwtCredentialQuery() {
        var query = new SdJwtCredentialConstrainer()
                .buildQuery(
                        SdJwtCredentialConstrainer.QuerySpec.of(List.of("https://example.com/vct"), List.of("sub")));
        assertDoesNotThrow(() -> DcqlQueryValidator.validateQuery(query));
    }

    @Test
    void acceptsValidJwtVcJsonCredentialQuery() {
        var query = new JwtVcJsonCredentialConstrainer()
                .buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                        List.of(List.of("VerifiableCredential", "IDCredential")),
                        List.of(List.of("credentialSubject", "given_name")),
                        null));
        assertDoesNotThrow(() -> DcqlQueryValidator.validateQuery(query));
    }
}
