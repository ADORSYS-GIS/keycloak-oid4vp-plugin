package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.keycloak.Config;

class OID4VPConfigTest {

    @Test
    void shouldDefaultToNoAutoCreatedRealms() {
        OID4VPConfig config = new OID4VPConfig(null);

        assertFalse(config.shouldAutoCreateAuthFlowFor("any-realm"));
    }

    @Test
    void shouldTreatMissingConfigKeyAsEmpty() {
        Config.Scope scope = mock(Config.Scope.class);

        OID4VPConfig config = new OID4VPConfig(scope);

        assertFalse(config.shouldAutoCreateAuthFlowFor("any-realm"));
    }

    @Test
    void shouldHonourCommaSeparatedRealmList() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.get("managed-realms")).thenReturn("test, dev , preview");

        OID4VPConfig config = new OID4VPConfig(scope);

        assertTrue(config.shouldAutoCreateAuthFlowFor("test"));
        assertTrue(config.shouldAutoCreateAuthFlowFor("dev"));
        assertTrue(config.shouldAutoCreateAuthFlowFor("preview"));
        assertFalse(config.shouldAutoCreateAuthFlowFor("production"));
    }

    @Test
    void shouldTreatEmptyValueAsDisabled() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.get("managed-realms")).thenReturn("");

        OID4VPConfig config = new OID4VPConfig(scope);

        assertFalse(config.shouldAutoCreateAuthFlowFor("any-realm"));
    }

    @Test
    void shouldTreatBlankValueAsDisabled() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.get("managed-realms")).thenReturn("   ");

        OID4VPConfig config = new OID4VPConfig(scope);

        assertFalse(config.shouldAutoCreateAuthFlowFor("any-realm"));
    }

    @Test
    void shouldReturnFalseForBlankRealmName() {
        OID4VPConfig config = new OID4VPConfig(null);
        assertFalse(config.shouldAutoCreateAuthFlowFor(null));
        assertFalse(config.shouldAutoCreateAuthFlowFor(""));
        assertFalse(config.shouldAutoCreateAuthFlowFor("   "));
    }

    @Test
    void shouldHonourVerboseErrorsAndCacheMaxSize() {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.getBoolean("verbose-errors", false)).thenReturn(true);
        when(scope.getInt("cache-max-size", 1000)).thenReturn(2000);

        OID4VPConfig config = new OID4VPConfig(scope);

        assertTrue(config.verboseErrors());
        assertEquals(2000, config.cacheMaxSize());
    }
}
