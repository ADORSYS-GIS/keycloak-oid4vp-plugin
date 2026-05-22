package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class JwtVcJsonCredentialConstrainerTest {

    private final JwtVcJsonCredentialConstrainer constrainer = new JwtVcJsonCredentialConstrainer();

    @Test
    void buildsJwtVcJsonQueryWithTypeValuesAndVcRootPaths() {
        var typeValues = List.of(List.of("VerifiableCredential", "IDCredential"));
        var claimPaths =
                List.of(List.of("credentialSubject", "family_name"), List.of("credentialSubject", "given_name"));

        var query = constrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(typeValues, claimPaths, null));

        var credential = query.getCredentials().getFirst();
        assertEquals(VCFormat.JWT_VC, credential.getFormat());
        assertEquals(typeValues, credential.getMeta().getTypeValues());
        assertEquals(claimPaths, credential.getClaims().stream().map(claim -> claim.getPath()).toList());
    }
}
