package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Typed access to the user-import settings of one authentication profile.
 */
public class OID4VPImportConfig {

    private final boolean importUnknownUsers;
    private final String importIdentityProviderAlias;

    public OID4VPImportConfig(AuthenticationProfile profile) {
        this.importUnknownUsers = profile != null && profile.shouldImportUnknownUsers();
        this.importIdentityProviderAlias = profile == null
                ? AuthenticationProfile.DEFAULT_IMPORT_IDENTITY_PROVIDER_ALIAS
                : profile.getImportIdentityProviderAlias();
    }

    public boolean shouldImportUnknownUsers() {
        return importUnknownUsers;
    }

    public String getImportIdentityProviderAlias() {
        return importIdentityProviderAlias;
    }

    /**
     * Resolves the hidden import identity provider of this realm.
     *
     * @return the provider configuration backing user import
     * @throws IllegalStateException when the provider is missing, disabled, or has an unexpected
     *     provider id. Import must be refused in all three cases; the message tells the realm
     *     administrator exactly what to fix.
     */
    public IdentityProviderModel resolveImportIdentityProvider(KeycloakSession session, RealmModel realm) {
        IdentityProviderModel model = session.identityProviders().getByAlias(importIdentityProviderAlias);
        if (model == null) {
            throw new IllegalStateException(String.format(
                    "User import is enabled but no identity provider with alias '%s' exists in realm '%s'."
                            + " Create the hidden OpenID4VP Plugin Import provider first.",
                    importIdentityProviderAlias, realm.getName()));
        }
        if (!model.isEnabled()) {
            throw new IllegalStateException(String.format(
                    "User import is enabled but the identity provider '%s' in realm '%s' is disabled."
                            + " Enable the provider or disable user import.",
                    importIdentityProviderAlias, realm.getName()));
        }
        if (!OID4VPImportIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId())) {
            throw new IllegalStateException(String.format(
                    "User import is enabled but the identity provider '%s' in realm '%s' uses provider id '%s'"
                            + " instead of '%s'. Imported users must link against the OpenID4VP Plugin Import provider.",
                    importIdentityProviderAlias,
                    realm.getName(),
                    model.getProviderId(),
                    OID4VPImportIdentityProviderFactory.PROVIDER_ID));
        }
        return model;
    }
}
