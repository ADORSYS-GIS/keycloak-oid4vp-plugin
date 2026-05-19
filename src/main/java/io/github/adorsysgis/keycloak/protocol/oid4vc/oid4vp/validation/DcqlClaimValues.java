package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * Compares presented claim values against DCQL {@code values} constraints (§6.3, §6.4.1).
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
        if (actual.isTextual()) {
            return expected.equals(actual.asText());
        }
        if (actual.isBoolean()) {
            return expected.equalsIgnoreCase(String.valueOf(actual.asBoolean()));
        }
        if (actual.isIntegralNumber()) {
            return expected.equals(String.valueOf(actual.asLong()));
        }
        if (actual.isNumber()) {
            return expected.equals(String.valueOf(actual.asDouble()));
        }
        return expected.equals(actual.toString());
    }
}
