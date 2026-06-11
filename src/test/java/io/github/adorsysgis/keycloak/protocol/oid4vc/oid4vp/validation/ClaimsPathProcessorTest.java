package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClaimsPathProcessorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void selectsNestedClaim() throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        ObjectNode address = root.putObject("address");
        address.put("street_address", "42 Market Street");

        var selected = ClaimsPathProcessor.process(root, List.of("address", "street_address"));

        assertEquals(1, selected.size());
        assertEquals("42 Market Street", selected.getFirst().asText());
    }

    @Test
    void returnsEmptyWhenPathMissing() throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("name", "Arthur Dent");

        var selected = ClaimsPathProcessor.process(root, List.of("address", "street_address"));

        assertTrue(selected.isEmpty());
    }

    @Test
    void selectsClaimThroughNullArraySegment() throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode addresses = root.putArray("address");
        ObjectNode first = addresses.addObject();
        first.put("street_address", "1 Main Street");
        ObjectNode second = addresses.addObject();
        second.put("street_address", "2 Main Street");

        var selected = ClaimsPathProcessor.process(
                root, ClaimsPathProcessor.toPathComponents(Arrays.asList("address", null, "street_address")));

        assertEquals(2, selected.size());
        assertEquals("1 Main Street", selected.get(0).asText());
        assertEquals("2 Main Street", selected.get(1).asText());
    }

    @Test
    void selectsClaimUsingArrayIndex() throws Exception {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode scores = root.putArray("scores");
        scores.add(10);
        scores.add(20);

        var selected = ClaimsPathProcessor.process(root, ClaimsPathProcessor.toPathComponents(List.of("scores", 1)));

        assertEquals(1, selected.size());
        assertEquals(20, selected.getFirst().asInt());
    }

    @Test
    void deserializesMixedPathFromDcqlJson() throws Exception {
        Claim claim = MAPPER.readValue("""
                {
                  "path": ["address", null, "street_address"]
                }
                """, Claim.class);

        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode addresses = root.putArray("address");
        addresses.addObject().put("street_address", "42 Market Street");

        var selected = ClaimsPathProcessor.process(root, ClaimsPathProcessor.toPathComponents(claim.getPath()));

        assertEquals(1, selected.size());
        assertEquals("42 Market Street", selected.getFirst().asText());
    }

    @Test
    void rejectsUnsupportedPathComponent() {
        assertThrows(
                VpTokenValidationException.class, () -> ClaimsPathProcessor.toPathComponents(List.of("address", true)));
    }

    @Test
    void rejectsEmptyObjectKeySegment() {
        assertThrows(VpTokenValidationException.class, () -> ClaimsPathProcessor.toPathComponents(List.of("")));
    }

    @Test
    void rejectsObjectKeyWhenCurrentSelectionIsNotObject() {
        ObjectNode root = MAPPER.createObjectNode();
        root.putArray("address").add("not an object");

        assertThrows(
                VpTokenValidationException.class,
                () -> ClaimsPathProcessor.process(root, List.of("address", "street_address")));
    }

    @Test
    void rejectsObjectKeyAfterNullArraySegmentIncludesNonObject() {
        ObjectNode root = MAPPER.createObjectNode();
        ArrayNode addresses = root.putArray("address");
        addresses.add("not an object");
        addresses.addObject().put("street_address", "42 Market Street");

        assertThrows(
                VpTokenValidationException.class,
                () -> ClaimsPathProcessor.process(
                        root, ClaimsPathProcessor.toPathComponents(Arrays.asList("address", null, "street_address"))));
    }
}
