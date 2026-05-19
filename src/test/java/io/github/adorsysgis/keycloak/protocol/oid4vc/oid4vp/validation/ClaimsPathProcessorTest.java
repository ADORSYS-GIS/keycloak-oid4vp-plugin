package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
}
