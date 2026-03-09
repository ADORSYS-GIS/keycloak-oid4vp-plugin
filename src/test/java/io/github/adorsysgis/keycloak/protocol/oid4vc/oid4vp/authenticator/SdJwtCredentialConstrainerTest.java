package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer.QueryMap;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Constraints;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Filter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.model.Format;
import org.keycloak.util.JsonSerialization;

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
    void testGeneratePresentationDefinition() throws JsonProcessingException {
        List<String> vcts = List.of("vct1", "vct2");
        List<String> claims = List.of("name", "email");
        QueryMap queryMap = new QueryMap(vcts, claims);
        PresentationDefinition def = constrainer.generatePresentationDefinition(queryMap);
        System.out.println(JsonSerialization.mapper.writeValueAsString(def));
        assertPrexQuery(def, queryMap);
    }

    public static void assertDcqlQuery(DcqlQuery query, QueryMap map) {
        assertEquals(1, query.getCredentials().size());
        Credential credential = query.getCredentials().getFirst();

        assertEquals(Format.SD_JWT_VC, credential.getFormat());
        assertEquals(map.expectedVcts(), credential.getMeta().getVctValues());
        assertEquals(map.requiredClaims().size(), credential.getClaims().size());

        var paths = credential.getClaims().stream()
                .map(claim -> claim.getPath().getFirst())
                .toList();
        assertEquals(map.requiredClaims(), paths);
    }

    public static void assertPrexQuery(PresentationDefinition def, QueryMap map) {
        assertEquals(1, def.getInputDescriptors().size());

        var descriptor = def.getInputDescriptors().getFirst();
        var constraints = descriptor.getConstraints();
        var fields = constraints.getFields();

        var actualVcts = fields.stream()
                .filter(field -> field.getPath().getFirst().equals("$.vct"))
                .flatMap(field -> field.getFilter().getAnyOf().stream())
                .filter(filter -> filter.getType().equals(Filter.SimpleTypes.STRING))
                .map(Filter::getConst)
                .toList();

        var actualClaims = fields.stream()
                .filter(field -> !field.getPath().getFirst().equals("$.vct"))
                .map(field -> field.getPath().getFirst().substring(2)) // Remove "$."
                .toList();

        assertEquals(Constraints.LimitDisclosure.REQUIRED, constraints.getLimitDisclosure());
        assertEquals(map.expectedVcts(), actualVcts);
        assertEquals(map.requiredClaims(), actualClaims);
    }
}
