package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPConfig;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;

class ErrorResponseSanitizerTest {

    @AfterEach
    void resetConfigProperty() {
        OID4VPConfig.init(null);
    }

    @Test
    void shouldReturnGenericDescriptionByDefault() {
        OID4VPConfig.init(null);
        String correlationId = "test-ref-123";

        String description = ErrorResponseSanitizer.clientDescription(
                "Invalid verifiable presentation", "Detailed root cause", correlationId);

        assertEquals("Invalid verifiable presentation (ref: test-ref-123)", description);
    }

    @Test
    void shouldReturnDetailedDescriptionWhenVerboseErrorsEnabledViaProperty() {
        OID4VPConfig.init(newBooleanScope(true));

        String description = ErrorResponseSanitizer.clientDescription(
                "Invalid verifiable presentation", "Detailed root cause", "test-ref-123");

        assertEquals("Detailed root cause", description);
    }

    @Test
    void shouldGenerateNonBlankCorrelationIds() {
        String correlationId = ErrorResponseSanitizer.newCorrelationId();

        assertTrue(correlationId != null && !correlationId.isBlank());
    }

    private static Config.Scope newBooleanScope(boolean verboseErrors) {
        return new Config.Scope() {
            @Override
            public String get(String key) {
                return null;
            }

            @Override
            public String get(String key, String defaultValue) {
                return defaultValue;
            }

            @Override
            public String[] getArray(String key) {
                return null;
            }

            @Override
            public Integer getInt(String key) {
                return null;
            }

            @Override
            public Integer getInt(String key, Integer defaultValue) {
                return defaultValue;
            }

            @Override
            public Long getLong(String key) {
                return null;
            }

            @Override
            public Long getLong(String key, Long defaultValue) {
                return defaultValue;
            }

            @Override
            public Boolean getBoolean(String key) {
                return verboseErrors;
            }

            @Override
            public Boolean getBoolean(String key, Boolean defaultValue) {
                if ("verbose-errors".equals(key) || "verboseErrors".equals(key)) {
                    return verboseErrors;
                }
                return defaultValue;
            }

            @Override
            public Config.Scope scope(String... scope) {
                return this;
            }

            @Override
            public Config.Scope root() {
                return this;
            }

            @Override
            public Set<String> getPropertyNames() {
                return Set.of();
            }
        };
    }
}
