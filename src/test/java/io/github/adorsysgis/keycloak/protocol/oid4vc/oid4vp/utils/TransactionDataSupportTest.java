package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

class TransactionDataSupportTest {

    @Test
    void prepareWireEntryInjectsCredentialIds() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "payment");
        String raw = TransactionDataSupport.encodeWireObject(tx);

        String prepared = TransactionDataSupport.prepareWireEntry(raw, "my-credential");

        ObjectNode decoded = TransactionDataSupport.decodeWireObject(prepared);
        assertEquals(
                "my-credential",
                decoded.get(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).get(0).asText());
    }

    @Test
    void parseConfigValueReturnsEmptyForBlank() {
        assertEquals(List.of(), TransactionDataSupport.parseConfigValue("  "));
    }

    @Test
    void rejectsUnsupportedHashAlgorithm() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "payment");
        tx.putArray(TransactionDataSupport.HASH_ALGS_CLAIM).add("sha-512");
        String wire = TransactionDataSupport.encodeWireObject(tx);

        assertThrows(IllegalArgumentException.class, () -> TransactionDataSupport.allowedHashAlgorithms(wire));
    }

    @Test
    void parseConfigValueSplitsOnCommaAndNewline() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "t");
        String wire = TransactionDataSupport.encodeWireObject(tx);

        List<String> parsed = TransactionDataSupport.parseConfigValue(wire + "," + wire);
        assertEquals(2, parsed.size());
    }
}
