package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCProviderConfig;

/**
 * Overrides the default {@link OIDCLoginProtocolFactory} ({@code openid-connect}) with a higher
 * priority to provide the {@link PatchedOIDCLoginProtocol}, keeping the endpoint routing of the
 * base factory untouched.
 */
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
        return super.order() + 9; // Higher than default -> this factory wins for openid-connect
    }
}