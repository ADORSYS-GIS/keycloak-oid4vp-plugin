package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import org.junit.jupiter.api.Test;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderStorageProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Covers the user-import settings: safe defaults, overrides, and the hidden import provider
 * resolution that refuses clearly when the realm is misconfigured.
 */
class OID4VPImportConfigTest {

    @Test
    void defaultsKeepImportDisabled() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile());

        assertFalse(config.shouldImportUnknownUsers());
        assertEquals(
                AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS, config.getImportIdentityProviderAlias());
    }

    @Test
    void overridesAreRespected() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile()
                .setImportUnknownUsers(true)
                .setImportIdentityProviderAlias("custom-import"));

        assertTrue(config.shouldImportUnknownUsers());
        assertEquals("custom-import", config.getImportIdentityProviderAlias());
    }

    @Test
    void blankAliasFallsBackToDefault() {
        OID4VPImportConfig config =
                new OID4VPImportConfig(new AuthenticationProfile().setImportIdentityProviderAlias("  "));

        assertEquals(
                AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS, config.getImportIdentityProviderAlias());
    }

    @Test
    void aliasWithSurroundingWhitespaceIsTrimmed() {
        OID4VPImportConfig config =
                new OID4VPImportConfig(new AuthenticationProfile().setImportIdentityProviderAlias("  custom-import  "));

        assertEquals("custom-import", config.getImportIdentityProviderAlias());
    }

    @Test
    void resolvesProviderUsingConfiguredAlias() {
        OID4VPImportConfig config =
                new OID4VPImportConfig(new AuthenticationProfile().setImportIdentityProviderAlias("custom-import"));
        IdentityProviderModel provider = idpModel(true, true);
        provider.setAlias("custom-import");

        IdentityProviderModel resolved =
                config.resolveImportIdentityProvider(sessionWith("custom-import", provider), realm());

        assertEquals("custom-import", resolved.getAlias());
    }

    @Test
    void resolvesEnabledImportProvider() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile().setImportUnknownUsers(true));

        IdentityProviderModel resolved =
                config.resolveImportIdentityProvider(sessionWith(idpModel(true, true)), realm());

        assertEquals(AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS, resolved.getAlias());
    }

    @Test
    void missingProviderFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile());
        IllegalStateException e = assertThrows(
                IllegalStateException.class, () -> config.resolveImportIdentityProvider(sessionWith(null), realm()));
        assertTrue(e.getMessage().contains("No identity provider with alias"));
    }

    @Test
    void disabledProviderFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile());

        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                () -> config.resolveImportIdentityProvider(sessionWith(idpModel(true, false)), realm()));
        assertTrue(e.getMessage().contains("disabled"));
    }

    @Test
    void wrongProviderIdFailsClearly() {
        OID4VPImportConfig config = new OID4VPImportConfig(new AuthenticationProfile());
        IdentityProviderModel model = idpModel(true, true);
        model.setProviderId("oidc");

        IllegalStateException e = assertThrows(
                IllegalStateException.class, () -> config.resolveImportIdentityProvider(sessionWith(model), realm()));
        assertTrue(e.getMessage().contains(OID4VPImportIdentityProviderFactory.PROVIDER_ID));
    }

    private static IdentityProviderModel idpModel(boolean correctProviderId, boolean enabled) {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS);
        model.setProviderId(correctProviderId ? OID4VPImportIdentityProviderFactory.PROVIDER_ID : "oid4vp");
        model.setEnabled(enabled);
        return model;
    }

    private static KeycloakSession sessionWith(IdentityProviderModel idp) {
        return sessionWith(AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS, idp);
    }

    private static KeycloakSession sessionWith(String alias, IdentityProviderModel idp) {
        IdentityProviderStorageProvider storage = mock(IdentityProviderStorageProvider.class);
        when(storage.getByAlias(alias)).thenReturn(idp);
        KeycloakSession session = mock(KeycloakSession.class);
        when(session.identityProviders()).thenReturn(storage);
        return session;
    }

    private static RealmModel realm() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test");
        return realm;
    }
}
