package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Typed access to the user-import authenticator settings.
 *
 * <p>Read full descriptions of the settings in {@link OID4VPAuthenticatorFactory}.
 */
public class OID4VPImportConfig {

    private static final Logger logger = Logger.getLogger(OID4VPImportConfig.class);

    private final boolean importUnknownUsers;
    private final String importIdentityProviderAlias;

    public OID4VPImportConfig(AuthenticatorConfigModel authConfig) {
        logger.debugf("Collecting user import properties");

        Map<String, String> config =
                (authConfig != null && authConfig.getConfig() != null) ? authConfig.getConfig() : Map.of();

        this.importUnknownUsers = Boolean.parseBoolean(config.getOrDefault(
                OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG,
                String.valueOf(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG_DEFAULT)));

        String alias = config.getOrDefault(
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG,
                OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT);
        this.importIdentityProviderAlias =
                alias != null && !alias.isBlank() ? alias : OID4VPAuthenticatorFactory.IMPORT_IDP_ALIAS_CONFIG_DEFAULT;
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
    public OID4VPImportIdentityProviderConfig resolveImportIdentityProvider(KeycloakSession session, RealmModel realm) {
        IdentityProviderModel model = realm.getIdentityProviderByAlias(importIdentityProviderAlias);
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
        return new OID4VPImportIdentityProviderConfig(model);
    }
}
