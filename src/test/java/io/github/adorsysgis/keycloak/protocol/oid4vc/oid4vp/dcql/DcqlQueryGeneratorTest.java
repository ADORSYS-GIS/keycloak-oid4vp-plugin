package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

    @Test
    void testGenerateMdocDcqlQuery() {
        List<String> docTypes = List.of("org.iso.18013.5.1.mDL");
        List<String> claims = List.of("org.iso.18013.5.1/given_name", "org.iso.18013.5.1/family_name");
        AuthenticationProfile profile = new AuthenticationProfile()
                .setId("mdoc")
                .setCredentials(List.of(new CredentialRequirement()
                        .setId("mdoc-credential")
                        .setRole(CredentialRole.PRIMARY)
                        .setFormat(CredentialFormat.MSO_MDOC.getValue())
                        .setCredentialTypes(docTypes)
                        .setClaims(claims)));

        DcqlQuery query = generator.buildQuery(profile, true);
        assertEquals(1, query.getCredentials().size());
        Credential credential = query.getCredentials().getFirst();

        assertEquals(CredentialFormat.MSO_MDOC.getValue(), credential.getFormat());
        assertEquals(docTypes.getFirst(), credential.getMeta().getDoctypeValue());

        List<Claim> generatedClaims = credential.getClaims();
        assertEquals(claims.size(), generatedClaims.size());

        Set<String> ids = new HashSet<>();
        for (int i = 0; i < claims.size(); i++) {
            Claim claim = generatedClaims.get(i);
            // claim ids are random UUIDs — unique and non-blank (one scheme for all formats)
            assertTrue(claim.getId() != null && !claim.getId().isBlank(), "claim id must not be blank");
            assertTrue(ids.add(claim.getId()), "claim ids must be unique: " + claim.getId());
            // path is [namespace, name] derived from the namespaced claim spec
            assertEquals(2, claim.getPath().size());
            var parts = claims.get(i).split(CredentialRequirement.ClaimReference.SEPARATOR);
            assertEquals(parts[0], claim.getPath().getFirst());
            assertEquals(parts[1], claim.getPath().get(1));
        }
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
