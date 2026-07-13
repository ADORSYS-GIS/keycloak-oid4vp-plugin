package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

public class DcqlQueryGeneratorTest {

    private final DcqlQueryGenerator generator = DcqlQueryGenerator.create();

    @Test
    void testGenerateDcqlQuery() {
        List<String> vcts = List.of("vct1", "vct2");
        List<String> claims = List.of("name", "email");
        DcqlQuery query = generator.buildQuery(singleCredentialProfile(vcts, claims), true);
        assertDcqlQuery(query, vcts, claims);
    }

    @Test
    void testGenerateDcqlQueryWithoutHolderBinding() {
        List<String> vcts = List.of("vct1");
        List<String> claims = List.of("name");
        DcqlQuery query = generator.buildQuery(singleCredentialProfile(vcts, claims), false);
        assertEquals(Boolean.FALSE, query.getCredentials().getFirst().getRequireCryptographicHolderBinding());
    }

    @Test
    void testGenerateMultiCredentialDcqlQuery() {
        AuthenticationProfile profile = new AuthenticationProfile()
                .setId("dual")
                .setCredentials(List.of(
                        new CredentialRequirement()
                                .setId("main")
                                .setRole(CredentialRole.PRIMARY)
                                .setCredentialTypes(List.of("main-vct"))
                                .setClaims(List.of("sub", "username")),
                        new CredentialRequirement()
                                .setId("supporting")
                                .setRole(CredentialRole.SUPPORTING)
                                .setCredentialTypes(List.of("supporting-vct"))
                                .setClaims(List.of("username"))));

        DcqlQuery query = generator.buildQuery(profile, true);

        assertEquals(2, query.getCredentials().size());
        assertEquals(
                List.of("main", "supporting"),
                query.getCredentials().stream().map(Credential::getId).toList());
        assertEquals(
                List.of("main", "supporting"),
                query.getCredentialSets().getFirst().getOptions().getFirst());
    }

    public static void assertDcqlQuery(DcqlQuery query, List<String> vctValues, List<String> claims) {
        assertEquals(1, query.getCredentials().size());
        Credential credential = query.getCredentials().getFirst();

        assertEquals(VCFormat.SD_JWT_VC, credential.getFormat());
        assertEquals(vctValues, credential.getMeta().getVctValues());
        assertEquals(claims.size(), credential.getClaims().size());

        var paths = credential.getClaims().stream()
                .map(claim -> claim.getPath().getFirst())
                .toList();
        assertEquals(claims, paths);
        assertEquals(Boolean.TRUE, credential.getRequireCryptographicHolderBinding());

        assertEquals(1, query.getCredentialSets().size());
        var credentialSet = query.getCredentialSets().getFirst();
        assertEquals(1, credentialSet.getOptions().size());
        assertEquals(List.of(credential.getId()), credentialSet.getOptions().getFirst());
    }

    public static AuthenticationProfile singleCredentialProfile(List<String> vctValues, List<String> claims) {
        return new AuthenticationProfile()
                .setId("test")
                .setCredentials(List.of(new CredentialRequirement()
                        .setId("credential")
                        .setRole(CredentialRole.PRIMARY)
                        .setCredentialTypes(vctValues)
                        .setClaims(claims)));
    }
}
