package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * Compares presented claim values against DCQL {@code values} constraints (§6.3, §6.4.1).
 *
 * <p>Matching is strict by JSON value type: a string constraint such as {@code "true"} only matches
 * a textual claim, not a boolean {@code true}; a string {@code "42"} only matches text, not numeric
 * {@code 42}. Use boolean/number entries in {@code values} when those types are intended.
 */
final class DcqlClaimValues {

    private DcqlClaimValues() {}

    static boolean matchesAny(List<JsonNode> resolved, List<Object> expectedValues) {
        if (expectedValues == null || expectedValues.isEmpty()) {
            return true;
        }
        for (JsonNode actual : resolved) {
            for (Object expected : expectedValues) {
                if (equals(actual, expected)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean equals(JsonNode actual, Object expected) {
        if (actual == null || expected == null) {
            return false;
        }
        if (expected instanceof String expectedString) {
            return equalsString(actual, expectedString);
        }
        if (expected instanceof Boolean expectedBoolean) {
            return actual.isBoolean() && actual.asBoolean() == expectedBoolean;
        }
        if (expected instanceof Integer expectedInteger) {
            return actual.isIntegralNumber() && actual.asInt() == expectedInteger;
        }
        if (expected instanceof Long expectedLong) {
            return actual.isIntegralNumber() && actual.asLong() == expectedLong;
        }
        if (expected instanceof Number expectedNumber) {
            return actual.isNumber() && actual.asDouble() == expectedNumber.doubleValue();
        }
        return expected.toString().equals(actual.isValueNode() ? actual.asText() : actual.toString());
    }

    private static boolean equalsString(JsonNode actual, String expected) {
        return actual.isTextual() && expected.equals(actual.asText());
    }
}
