package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.List;
import org.keycloak.utils.StringUtil;

/**
 * Validates KB-JWT {@code transaction_data_hashes} against OpenID4VP Final B.3.3.1.
 */
public final class TransactionDataValidator {

    public static final String TRANSACTION_DATA_HASHES_CLAIM = "transaction_data_hashes";
    public static final String TRANSACTION_DATA_HASHES_ALG_CLAIM = "transaction_data_hashes_alg";

    private TransactionDataValidator() {}

    public static void validate(List<String> transactionDataWire, ObjectNode kbJwtPayload) {
        if (transactionDataWire == null || transactionDataWire.isEmpty()) {
            return;
        }

        JsonNode hashesNode = kbJwtPayload.get(TRANSACTION_DATA_HASHES_CLAIM);
        if (hashesNode == null || !hashesNode.isArray() || hashesNode.isEmpty()) {
            throw new IllegalArgumentException("Key Binding JWT must contain transaction_data_hashes");
        }

        if (hashesNode.size() != transactionDataWire.size()) {
            throw new IllegalArgumentException(String.format(
                    "transaction_data_hashes length (%d) must match transaction_data length (%d)",
                    hashesNode.size(), transactionDataWire.size()));
        }

        List<Boolean> requestSpecifiedAlg = new ArrayList<>();
        for (String wire : transactionDataWire) {
            ObjectNode decoded = TransactionDataSupport.decodeWireObject(wire);
            requestSpecifiedAlg.add(decoded.has(TransactionDataSupport.HASH_ALGS_CLAIM));
        }

        boolean anyRequestAlg = requestSpecifiedAlg.stream().anyMatch(Boolean::booleanValue);
        String kbAlg = null;
        if (anyRequestAlg) {
            JsonNode algNode = kbJwtPayload.get(TRANSACTION_DATA_HASHES_ALG_CLAIM);
            if (algNode == null || !algNode.isTextual() || StringUtil.isBlank(algNode.asText())) {
                throw new IllegalArgumentException(
                        "Key Binding JWT must contain transaction_data_hashes_alg when request specified transaction_data_hashes_alg");
            }
            kbAlg = algNode.asText();
        }

        for (int i = 0; i < transactionDataWire.size(); i++) {
            String wire = transactionDataWire.get(i);
            List<String> allowedAlgs = TransactionDataSupport.allowedHashAlgorithms(wire);
            String hashAlg = kbAlg;
            if (hashAlg == null) {
                hashAlg = TransactionDataSupport.DEFAULT_HASH_ALG;
            }
            if (!allowedAlgs.contains(hashAlg)) {
                throw new IllegalArgumentException(String.format(
                        "transaction_data_hashes_alg '%s' is not among allowed algorithms %s for transaction_data entry %d",
                        hashAlg, allowedAlgs, i));
            }

            String expectedHash =
                    TransactionDataSupport.base64UrlEncodeHash(TransactionDataSupport.hashWireString(wire, hashAlg));
            String presentedHash = hashesNode.get(i).asText();
            if (!expectedHash.equals(presentedHash)) {
                throw new IllegalArgumentException("transaction_data_hashes mismatch at index " + i);
            }
        }
    }
}
