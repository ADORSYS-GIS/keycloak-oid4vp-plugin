package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Factory of the hidden OpenID4VP Plugin Import identity provider.
 *
 * <p>The provider id deliberately differs from Keycloak's upstream {@code oid4vp} broker so both
 * implementations can coexist.
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
        return new OID4VPImportIdentityProvider(session, model);
    }

    @Override
    public IdentityProviderModel createConfig() {
        return new IdentityProviderModel();
    }
}
