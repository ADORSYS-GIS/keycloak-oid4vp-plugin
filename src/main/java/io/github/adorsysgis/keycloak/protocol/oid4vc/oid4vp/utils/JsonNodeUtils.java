package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import com.fasterxml.jackson.databind.JsonNode;

/** Utilities for reading typed values from JSON protocol payloads. */
public final class JsonNodeUtils {

    private JsonNodeUtils() {}

    /**
     * Returns the optional JSON string value for {@code field}.
     *
     * @throws IllegalArgumentException when the field is present but is not a JSON string
     */
    public static String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            throw new IllegalArgumentException(String.format("Field '%s' must be a JSON string", field));
        }
        return value.textValue();
    }
}
