package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.List;
import org.junit.jupiter.api.Test;

class DcqlClaimValuesTest {

    @Test
    void matchesStringValue() throws Exception {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.textNode("alice"));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of("alice")));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of("bob")));
    }

    @Test
    void matchesBooleanValue() throws Exception {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.booleanNode(true));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of(true)));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of(false)));
    }

    @Test
    void matchesIntegerValue() throws Exception {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.numberNode(42));

        assertTrue(DcqlClaimValues.matchesAny(resolved, List.of(42)));
        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of(7)));
    }

    @Test
    void doesNotCoerceStringConstraintToOtherJsonTypes() throws Exception {
        assertFalse(DcqlClaimValues.matchesAny(List.of(JsonNodeFactory.instance.booleanNode(true)), List.of("true")));
        assertFalse(DcqlClaimValues.matchesAny(List.of(JsonNodeFactory.instance.numberNode(42)), List.of("42")));
    }

    @Test
    void rejectsNonIntegralValueConstraint() {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.numberNode(42));

        assertThrows(VpTokenValidationException.class, () -> DcqlClaimValues.matchesAny(resolved, List.of(3.14)));
    }

    @Test
    void doesNotMatchDecimalClaimAgainstIntegerConstraint() throws Exception {
        List<JsonNode> resolved = List.of(JsonNodeFactory.instance.numberNode(3.14));

        assertFalse(DcqlClaimValues.matchesAny(resolved, List.of(3)));
    }
}
