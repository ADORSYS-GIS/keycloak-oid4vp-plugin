package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.oidc.OIDCProviderConfig;

/**
 * Overrides the default {@link OIDCLoginProtocolFactory} ({@code openid-connect}) with a higher
 * priority to provide the {@link ExtendedOIDCLoginProtocol} and the
 * {@link ExtendedOIDCLoginProtocolService} endpoint, keeping the rest of the base factory untouched.
 */
public class ExtendedOIDCLoginProtocolFactory extends OIDCLoginProtocolFactory {

    private OIDCProviderConfig providerConfig;

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.providerConfig = new OIDCProviderConfig(config);
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new ExtendedOIDCLoginProtocol(providerConfig).setSession(session);
    }

    @Override
    public Object createProtocolEndpoint(KeycloakSession session, EventBuilder event) {
        return new ExtendedOIDCLoginProtocolService(session, event);
    }

    @Override
    public int order() {
        return super.order() + 9;
    }
}
