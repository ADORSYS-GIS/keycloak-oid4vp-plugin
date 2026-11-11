package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCProviderConfig;

public class PatchedOIDCLoginProtocolFactory extends OIDCLoginProtocolFactory {

    private OIDCProviderConfig providerConfig;

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        super.postInit(factory);
        try (KeycloakSession session = factory.create()) {
            this.providerConfig = ((OIDCLoginProtocol) super.create(session)).getConfig();
        }
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
