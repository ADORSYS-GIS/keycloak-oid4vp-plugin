package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Covers the user-import settings: safe defaults, overrides, and the hidden import provider
 * resolution that refuses clearly when the realm is misconfigured.
 */
class OID4VPImportConfigTest {

    @Test
    void defaultsKeepImportDisabled() {
        OID4VPImportConfig config = new OID4VPImportConfig(null);

        assertFalse(config.shouldImportUnknownUsers());
        assertEquals(
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT, config.getImportIdentityProviderAlias());
    }

    @Test
    void emptyConfigKeepsImportDisabled() {
        OID4VPImportConfig config = new OID4VPImportConfig(authConfig(Map.of()));

        assertFalse(config.shouldImportUnknownUsers());
        assertEquals(
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT, config.getImportIdentityProviderAlias());
    }

    @Test
    void overridesAreRespected() {
        OID4VPImportConfig config = new OID4VPImportConfig(authConfig(Map.of(
                OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true",
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG, "custom-import")));

        assertTrue(config.shouldImportUnknownUsers());
        assertEquals("custom-import", config.getImportIdentityProviderAlias());
    }

    @Test
    void blankAliasFallsBackToDefault() {
        OID4VPImportConfig config =
                new OID4VPImportConfig(authConfig(Map.of(OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG, "  ")));

        assertEquals(
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT, config.getImportIdentityProviderAlias());
    }

    @Test
    void resolvesEnabledImportProvider() {
        OID4VPImportConfig config = new OID4VPImportConfig(
                authConfig(Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true")));

        OID4VPImportIdentityProviderConfig resolved =
                config.resolveImportIdentityProvider(mock(KeycloakSession.class), realmWith(idpModel(true, true)));

        assertEquals(OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT, resolved.getAlias());
    }

    @Test
    void missingProviderFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(null);
        RealmModel realm = mock(RealmModel.class);
        when(realm.getIdentityProviderByAlias(OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT))
                .thenReturn(null);

        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                () -> config.resolveImportIdentityProvider(mock(KeycloakSession.class), realm));
        assertTrue(e.getMessage().contains("no identity provider"));
    }

    @Test
    void disabledProviderFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(null);

        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                () -> config.resolveImportIdentityProvider(
                        mock(KeycloakSession.class), realmWith(idpModel(true, false))));
        assertTrue(e.getMessage().contains("disabled"));
    }

    @Test
    void wrongProviderIdFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(null);
        IdentityProviderModel model = idpModel(true, true);
        model.setProviderId("oidc");

        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                () -> config.resolveImportIdentityProvider(mock(KeycloakSession.class), realmWith(model)));
        assertTrue(e.getMessage().contains(OID4VPImportIdentityProviderFactory.PROVIDER_ID));
    }

    private static AuthenticatorConfigModel authConfig(Map<String, String> values) {
        AuthenticatorConfigModel model = new AuthenticatorConfigModel();
        model.setConfig(new HashMap<>(values));
        return model;
    }

    private static IdentityProviderModel idpModel(boolean correctProviderId, boolean enabled) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT);
        model.setProviderId(correctProviderId ? OID4VPImportIdentityProviderFactory.PROVIDER_ID : "oid4vp");
        model.setEnabled(enabled);
        return model;
    }

    private static RealmModel realmWith(IdentityProviderModel idp) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getIdentityProviderByAlias(idp.getAlias())).thenReturn(idp);
        when(realm.getName()).thenReturn("test");
        return realm;
    }
}
