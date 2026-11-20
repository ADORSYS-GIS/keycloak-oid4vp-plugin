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
     *     provider id. The caller decides whether this prevents user creation or skips
     *     synchronization.
     */
    public IdentityProviderModel resolveImportIdentityProvider(KeycloakSession session, RealmModel realm) {
        IdentityProviderModel model = session.identityProviders().getByAlias(importIdentityProviderAlias);
        if (model == null) {
            throw new IllegalStateException(String.format(
                    "No identity provider with alias '%s' exists in realm '%s'."
                            + " Create an OpenID4VP Plugin Import provider with this alias.",
                    importIdentityProviderAlias, realm.getName()));
        }
        if (!model.isEnabled()) {
            throw new IllegalStateException(String.format(
                    "Identity provider '%s' in realm '%s' is disabled."
                            + " Enable it to use OpenID4VP user import or synchronization.",
                    importIdentityProviderAlias, realm.getName()));
        }
        if (!OID4VPImportIdentityProviderFactory.PROVIDER_ID.equals(model.getProviderId())) {
            throw new IllegalStateException(String.format(
                    "Identity provider '%s' in realm '%s' uses provider id '%s' instead of '%s'."
                            + " Configure this alias to use the OpenID4VP Plugin Import provider.",
                    importIdentityProviderAlias,
                    realm.getName(),
                    model.getProviderId(),
                    OID4VPImportIdentityProviderFactory.PROVIDER_ID));
        }
        return model;
    }
}
