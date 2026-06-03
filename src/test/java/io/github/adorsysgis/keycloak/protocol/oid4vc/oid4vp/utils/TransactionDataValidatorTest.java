package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

class TransactionDataValidatorTest {

    @Test
    void validateAcceptsSha256HashOverWireString() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "example_type");
        tx.putArray(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).add("cred-1");
        String wire = TransactionDataSupport.encodeWireObject(tx);

        String hash = TransactionDataSupport.base64UrlEncodeHash(
                TransactionDataSupport.hashWireString(wire, TransactionDataSupport.DEFAULT_HASH_ALG));

        ObjectNode kbJwt = JsonSerialization.mapper.createObjectNode();
        ArrayNode hashes = kbJwt.putArray(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM);
        hashes.add(hash);

        assertDoesNotThrow(() -> TransactionDataValidator.validate(List.of(wire), kbJwt));
    }

    @Test
    void validateRejectsWrongHash() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "example_type");
        tx.putArray(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).add("cred-1");
        String wire = TransactionDataSupport.encodeWireObject(tx);

        ObjectNode kbJwt = JsonSerialization.mapper.createObjectNode();
        ArrayNode hashes = kbJwt.putArray(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM);
        hashes.add("not-a-valid-hash");

        assertThrows(IllegalArgumentException.class, () -> TransactionDataValidator.validate(List.of(wire), kbJwt));
    }

    @Test
    void validateRequiresKbAlgWhenRequestSpecifiedAlgs() {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, "example_type");
        tx.putArray(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).add("cred-1");
        tx.putArray(TransactionDataSupport.HASH_ALGS_CLAIM).add("sha-256");
        String wire = TransactionDataSupport.encodeWireObject(tx);

        String hash = TransactionDataSupport.base64UrlEncodeHash(
                TransactionDataSupport.hashWireString(wire, TransactionDataSupport.DEFAULT_HASH_ALG));

        ObjectNode kbJwt = JsonSerialization.mapper.createObjectNode();
        kbJwt.putArray(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM).add(hash);

        assertThrows(IllegalArgumentException.class, () -> TransactionDataValidator.validate(List.of(wire), kbJwt));
    }
}
