package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Factory of the hidden OpenID4VP Plugin Import identity provider.
 *
 * <p>The provider id deliberately differs from upstream Keycloak's {@code oid4vp} broker so both
 * can coexist once upstream support ships.
 */
public class OID4VPImportIdentityProviderFactory extends AbstractIdentityProviderFactory<OID4VPImportIdentityProvider>
        implements OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "oid4vp-plugin-import";

    @Override
    public String getName() {
        return "OpenID4VP Plugin Import";
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public OID4VPImportIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OID4VPImportIdentityProvider(session, new OID4VPImportIdentityProviderConfig(model));
    }

    @Override
    public OID4VPImportIdentityProviderConfig createConfig() {
        return new OID4VPImportIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }
}
