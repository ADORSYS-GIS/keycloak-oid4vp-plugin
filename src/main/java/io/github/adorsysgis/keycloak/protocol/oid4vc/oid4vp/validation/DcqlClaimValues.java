package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/**
 * Compares presented claim values against DCQL {@code values} constraints (§6.3, §6.4.1).
 *
 * <p>DCQL allows only strings, integers, and booleans in {@code values}. Matching is strict by JSON value
 * type: a string constraint such as {@code "true"} only matches a textual claim, not a boolean
 * {@code true}; a string {@code "42"} only matches text, not numeric {@code 42}.
 */
final class DcqlClaimValues {

    private DcqlClaimValues() {}

    static boolean matchesAny(List<JsonNode> resolved, List<Object> expectedValues) throws VpTokenValidationException {
        if (expectedValues == null || expectedValues.isEmpty()) {
            return true;
        }
        validateExpectedValues(expectedValues);
        for (JsonNode actual : resolved) {
            for (Object expected : expectedValues) {
                if (equals(actual, expected)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void validateExpectedValues(List<Object> expectedValues) throws VpTokenValidationException {
        for (Object expected : expectedValues) {
            validateExpectedValue(expected);
        }
    }

    private static void validateExpectedValue(Object expected) throws VpTokenValidationException {
        if (expected == null) {
            throw invalidValueType(null);
        }
        if (expected instanceof String || expected instanceof Boolean) {
            return;
        }
        if (expected instanceof Integer || expected instanceof Long) {
            return;
        }
        if (expected instanceof Number number) {
            if (!isIntegral(number)) {
                throw invalidValueType(expected);
            }
            return;
        }
        throw invalidValueType(expected);
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
            return equalsIntegral(actual, expectedInteger.longValue());
        }
        if (expected instanceof Long expectedLong) {
            return equalsIntegral(actual, expectedLong);
        }
        if (expected instanceof Number number && isIntegral(number)) {
            return equalsIntegral(actual, number.longValue());
        }
        return false;
    }

    private static boolean equalsIntegral(JsonNode actual, long expected) {
        return actual.isIntegralNumber() && actual.asLong() == expected;
    }

    private static boolean isIntegral(Number number) {
        return number.doubleValue() == Math.rint(number.doubleValue()) && !Double.isInfinite(number.doubleValue());
    }

    private static boolean equalsString(JsonNode actual, String expected) {
        return actual.isTextual() && expected.equals(actual.asText());
    }

    private static VpTokenValidationException invalidValueType(Object expected) {
        return new VpTokenValidationException(
                VpTokenValidationException.Phase.DCQL,
                "DCQL values entry must be a string, boolean, or integer, but was: " + expected);
    }
}
