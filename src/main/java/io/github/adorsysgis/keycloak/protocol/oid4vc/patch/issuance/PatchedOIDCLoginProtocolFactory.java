package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCProviderConfig;

public class PatchedOIDCLoginProtocolFactory extends OIDCLoginProtocolFactory {

    private OIDCProviderConfig providerConfig;

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.providerConfig = new OIDCProviderConfig(config);
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new PatchedOIDCLoginProtocol(providerConfig).setSession(session);
    }

    @Override
    public int order() {
        return super.order() + 9;
    }
}
