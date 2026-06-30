package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for the OID4VCI "presentation during issuance" authorization challenge endpoint
 * (RFC 9470 OAuth 2.0 Authorization Challenge).
 */
public class AuthorizationChallengeEndpointFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "oid4vci-authorization-challenge";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        EventBuilder event = new EventBuilder(realm, session, context.getConnection());
        return new AuthorizationChallengeEndpoint(session, event);
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}
}
