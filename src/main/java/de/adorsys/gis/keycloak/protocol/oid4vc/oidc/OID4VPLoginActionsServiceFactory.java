package de.adorsys.gis.keycloak.protocol.oid4vc.oidc;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.OID4VPEnvironmentProviderFactory;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class OID4VPLoginActionsServiceFactory
        implements RealmResourceProviderFactory, OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "oid4vp-login-actions";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        EventBuilder event = new EventBuilder(context.getRealm(), session, context.getConnection());
        return new OID4VPLoginActionsService(session, event);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
