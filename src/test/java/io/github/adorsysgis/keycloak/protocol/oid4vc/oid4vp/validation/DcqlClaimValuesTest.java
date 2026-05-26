package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.List;
import org.junit.jupiter.api.Test;

class DcqlClaimValuesTest {

    @Test
    void matchesStringValue() {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.textNode("alice"));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of("alice")));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of("bob")));
    }

    @Test
    void matchesBooleanValue() {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.booleanNode(true));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of(true)));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of(false)));
    }

    @Test
    void matchesIntegerValue() {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.numberNode(42));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of(42)));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of(7)));
    }

    @Test
    void doesNotCoerceStringConstraintToOtherJsonTypes() {
        assertFalse(DcqlClaimValues.matchesAny(List.of(JsonNodeFactory.instance.booleanNode(true)), List.of("true")));
        assertFalse(DcqlClaimValues.matchesAny(List.of(JsonNodeFactory.instance.numberNode(42)), List.of("42")));
    }
}
