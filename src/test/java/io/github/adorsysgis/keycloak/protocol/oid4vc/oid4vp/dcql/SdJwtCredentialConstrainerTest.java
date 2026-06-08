package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer.QuerySpec.of;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.SdJwtCredentialConstrainer.QuerySpec;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

public class SdJwtCredentialConstrainerTest {

    private final SdJwtCredentialConstrainer constrainer = SdJwtCredentialConstrainer.create();

    @Test
    void testGenerateDcqlQuery() {
        List<String> vcts = List.of("vct1", "vct2");
        List<String> claims = List.of("name", "email");
        QuerySpec spec = of(vcts, claims);
        DcqlQuery query = constrainer.buildQuery(spec);
        assertDcqlQuery(query, spec);
    }

    @Test
    void testGenerateDcqlQueryWithoutHolderBinding() {
        List<String> vcts = List.of("vct1");
        List<String> claims = List.of("name");
        QuerySpec spec = of(vcts, claims, false);
        DcqlQuery query = constrainer.buildQuery(spec);
        assertEquals(Boolean.FALSE, query.getCredentials().getFirst().getRequireCryptographicHolderBinding());
    }

    public static void assertDcqlQuery(DcqlQuery query, QuerySpec spec) {
        assertEquals(1, query.getCredentials().size());
        Credential credential = query.getCredentials().getFirst();

        assertEquals(VCFormat.SD_JWT_VC, credential.getFormat());
        assertEquals(spec.vctValues(), credential.getMeta().getVctValues());
        assertEquals(spec.claimPaths().size(), credential.getClaims().size());

        var paths = credential.getClaims().stream()
                .map(claim -> claim.getPath().getFirst())
                .toList();
        var expectedPaths =
                spec.claimPaths().stream().map(path -> path.getFirst()).toList();
        assertEquals(expectedPaths, paths);
        assertEquals(
                spec.requireCryptographicHolderBinding() != null
                        ? spec.requireCryptographicHolderBinding()
                        : Boolean.TRUE,
                credential.getRequireCryptographicHolderBinding());

        assertEquals(1, query.getCredentialSets().size());
        var credentialSet = query.getCredentialSets().getFirst();
        assertEquals(1, credentialSet.getOptions().size());
        assertEquals(List.of(credential.getId()), credentialSet.getOptions().getFirst());
    }
}
