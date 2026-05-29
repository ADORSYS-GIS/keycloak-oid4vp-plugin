package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer.QueryMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

public class SdJwtCredentialConstrainerTest {

    SdJwtCredentialConstrainer constrainer = new SdJwtCredentialConstrainer();

    @Test
    void testGenerateDcqlQuery() {
        List<String> vcts = List.of("vct1", "vct2");
        List<String> claims = List.of("name", "email");
        QueryMap queryMap = new QueryMap(vcts, claims);
        DcqlQuery query = constrainer.generateDcqlQuery(queryMap);
        assertDcqlQuery(query, queryMap);
    }

    @Test
    void testGenerateDcqlQueryWithoutHolderBinding() {
        List<String> vcts = List.of("vct1");
        List<String> claims = List.of("name");
        QueryMap queryMap = new QueryMap(vcts, claims, false);
        DcqlQuery query = constrainer.generateDcqlQuery(queryMap);
        assertEquals(Boolean.FALSE, query.getCredentials().getFirst().getRequireCryptographicHolderBinding());
    }

    public static void assertDcqlQuery(DcqlQuery query, QueryMap map) {
        assertEquals(1, query.getCredentials().size());
        Credential credential = query.getCredentials().getFirst();

        assertEquals(VCFormat.SD_JWT_VC, credential.getFormat());
        assertEquals(map.expectedVcts(), credential.getMeta().getVctValues());
        assertEquals(map.requiredClaims().size(), credential.getClaims().size());

        var paths = credential.getClaims().stream()
                .map(claim -> (String) claim.getPath().getFirst())
                .toList();
        assertEquals(map.requiredClaims(), paths);

        // Assert credential sets
        assertEquals(1, query.getCredentialSets().size());
        var credentialSet = query.getCredentialSets().getFirst();
        assertEquals(1, credentialSet.getOptions().size());
        assertEquals(List.of(credential.getId()), credentialSet.getOptions().getFirst());
    }
}
