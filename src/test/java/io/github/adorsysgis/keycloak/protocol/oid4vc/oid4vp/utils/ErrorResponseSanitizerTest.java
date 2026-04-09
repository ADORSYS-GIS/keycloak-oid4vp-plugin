package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;

class ErrorResponseSanitizerTest {

    @AfterEach
    void resetConfigProperty() {
        ErrorResponseSanitizer.init(new OID4VPConfig(null));
    }

    @Test
    void shouldReturnGenericDescriptionByDefault() {
        ErrorResponseSanitizer.init(new OID4VPConfig(null));
        String correlationId = "test-ref-123";

        String description = ErrorResponseSanitizer.clientDescription(
                "Invalid verifiable presentation", "Detailed root cause", correlationId);

        assertEquals("Invalid verifiable presentation (ref: test-ref-123)", description);
    }

    @Test
    void shouldReturnDetailedDescriptionWhenVerboseErrorsEnabledViaProperty() {
        Config.Scope config = mock(Config.Scope.class);
        when(config.getBoolean(eq("verbose-errors"), anyBoolean())).thenReturn(true);
        ErrorResponseSanitizer.init(new OID4VPConfig(config));

        String description = ErrorResponseSanitizer.clientDescription(
                "Invalid verifiable presentation", "Detailed root cause", "test-ref-123");

        assertEquals("Detailed root cause (ref: test-ref-123)", description);
    }

    @Test
    void shouldGenerateNonBlankCorrelationIds() {
        String correlationId = ErrorResponseSanitizer.newCorrelationId();

        assertTrue(correlationId != null && !correlationId.isBlank());
    }
}
