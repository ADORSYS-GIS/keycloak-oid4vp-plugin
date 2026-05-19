package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Prepares OpenID4VP {@code transaction_data} request parameter values per Final §5.1 and B.3.3.1.
 */
public final class TransactionDataSupport {

    public static final String DEFAULT_HASH_ALG = "sha-256";
    public static final String TYPE_CLAIM = "type";
    public static final String CREDENTIAL_IDS_CLAIM = "credential_ids";
    public static final String HASH_ALGS_CLAIM = "transaction_data_hashes_alg";

    private TransactionDataSupport() {}

    /**
     * Parses authenticator configuration into raw wire strings (trimmed, non-blank).
     */
    public static List<String> parseConfigValue(String transactionDataConfig) {
        if (StringUtil.isBlank(transactionDataConfig)) {
            return List.of();
        }

        String normalized = transactionDataConfig.trim();
        String[] parts = normalized.contains("\n") ? normalized.split("\\R") : normalized.split("\\s*,\\s*");

        List<String> wires = new ArrayList<>();
        for (String part : parts) {
            if (!StringUtil.isBlank(part)) {
                wires.add(part.trim());
            }
        }
        if (wires.isEmpty()) {
            throw new IllegalArgumentException("transactionData must contain at least one base64url-encoded entry");
        }
        return wires;
    }

    /**
     * Validates each entry and ensures {@code credential_ids} references the DCQL credential id.
     * Returns the wire strings as they must appear on the signed request (re-encoded when normalized).
     */
    public static List<String> prepareWireEntries(List<String> rawWireStrings, String dcqlCredentialId) {
        List<String> prepared = new ArrayList<>();
        for (String raw : rawWireStrings) {
            prepared.add(prepareWireEntry(raw, dcqlCredentialId));
        }
        return prepared;
    }

    public static String prepareWireEntry(String rawWire, String dcqlCredentialId) {
        ObjectNode object = decodeWireObject(rawWire);
        if (!object.hasNonNull(TYPE_CLAIM)
                || StringUtil.isBlank(object.get(TYPE_CLAIM).asText())) {
            throw new IllegalArgumentException("transaction_data object must contain a non-empty type");
        }

        if (!object.has(CREDENTIAL_IDS_CLAIM)
                || !object.get(CREDENTIAL_IDS_CLAIM).isArray()) {
            ArrayNode credentialIds = JsonSerialization.mapper.createArrayNode();
            credentialIds.add(dcqlCredentialId);
            object.set(CREDENTIAL_IDS_CLAIM, credentialIds);
        } else {
            ArrayNode credentialIds = (ArrayNode) object.get(CREDENTIAL_IDS_CLAIM);
            if (credentialIds.isEmpty()) {
                throw new IllegalArgumentException("transaction_data credential_ids must be a non-empty array");
            }
            boolean matches = false;
            for (JsonNode id : credentialIds) {
                if (dcqlCredentialId.equals(id.asText())) {
                    matches = true;
                    break;
                }
            }
            if (!matches) {
                throw new IllegalArgumentException(String.format(
                        "transaction_data credential_ids must reference DCQL credential id '%s'", dcqlCredentialId));
            }
        }

        return encodeWireObject(object);
    }

    public static ObjectNode decodeWireObject(String wire) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(wire);
            JsonNode node = JsonSerialization.mapper.readTree(decoded);
            if (!node.isObject()) {
                throw new IllegalArgumentException("transaction_data must decode to a JSON object");
            }
            return (ObjectNode) node;
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid base64url-encoded transaction_data entry", e);
        }
    }

    public static String encodeWireObject(ObjectNode object) {
        try {
            byte[] json = JsonSerialization.mapper.writeValueAsBytes(object);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to encode transaction_data object", e);
        }
    }

    /**
     * Returns allowed hash algorithm identifiers for a wire entry (default {@link #DEFAULT_HASH_ALG}).
     */
    public static List<String> allowedHashAlgorithms(String wire) {
        ObjectNode object = decodeWireObject(wire);
        if (!object.has(HASH_ALGS_CLAIM)) {
            return List.of(DEFAULT_HASH_ALG);
        }
        JsonNode algs = object.get(HASH_ALGS_CLAIM);
        if (!algs.isArray() || algs.isEmpty()) {
            throw new IllegalArgumentException("transaction_data_hashes_alg must be a non-empty array when present");
        }
        List<String> allowed = new ArrayList<>();
        for (JsonNode alg : algs) {
            if (!alg.isTextual() || StringUtil.isBlank(alg.asText())) {
                throw new IllegalArgumentException("transaction_data_hashes_alg entries must be non-empty strings");
            }
            allowed.add(alg.asText());
        }
        return allowed;
    }

    public static byte[] hashWireString(String wire, String hashAlg) {
        try {
            return java.security.MessageDigest.getInstance(normalizeDigestName(hashAlg))
                    .digest(wire.getBytes(StandardCharsets.UTF_8));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalArgumentException("Unsupported transaction_data hash algorithm: " + hashAlg, e);
        }
    }

    public static String base64UrlEncodeHash(byte[] hash) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    private static String normalizeDigestName(String hashAlg) {
        if (DEFAULT_HASH_ALG.equalsIgnoreCase(hashAlg)) {
            return "SHA-256";
        }
        return hashAlg;
    }
}
