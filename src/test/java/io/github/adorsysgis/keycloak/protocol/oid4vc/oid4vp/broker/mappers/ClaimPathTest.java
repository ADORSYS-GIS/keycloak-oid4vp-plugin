package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/**
 * Covers claim-path parsing and selection: nested claims, array fan-out, first-element selection,
 * escaped dots, and malformed paths.
 */
class ClaimPathTest {

    @Test
    void selectsNestedClaim() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"address\":{\"locality\":\"Berlin\"}}");

        assertEquals(
                List.of("Berlin"),
                ClaimPath.parse("address.locality").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void selectsAllArrayElements() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"nationalities\":[\"DE\",\"FR\"]}");

        assertEquals(
                List.of("DE", "FR"),
                ClaimPath.parse("nationalities[]").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void selectsFirstArrayElement() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"nationalities\":[\"DE\",\"FR\"]}");

        assertEquals(
                List.of("DE"),
                ClaimPath.parse("nationalities[0]").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void supportsEscapedDotInClaimName() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"a.b\":\"value\"}");

        assertEquals(
                List.of("value"),
                ClaimPath.parse("a\\.b").select(claims).stream()
                        .map(JsonNode::asText)
                        .toList());
    }

    @Test
    void missingPathsSelectNothing() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"given_name\":\"Ada\"}");

        assertTrue(ClaimPath.parse("family_name").select(claims).isEmpty());
        assertTrue(ClaimPath.parse("given_name[]").select(claims).isEmpty());
        assertTrue(ClaimPath.parse("address.locality").select(claims).isEmpty());
    }

    @Test
    void malformedPathsReturnNull() {
        assertNull(ClaimPath.parse(null));
        assertNull(ClaimPath.parse(""));
        assertNull(ClaimPath.parse("address."));
        assertNull(ClaimPath.parse("[0]"));
        assertNull(ClaimPath.parse("nationalities[1]"));
        assertNull(ClaimPath.parse("nationalities["));
    }
}
