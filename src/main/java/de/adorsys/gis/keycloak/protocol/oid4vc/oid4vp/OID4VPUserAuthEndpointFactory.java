package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

import static de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW;

/**
 * Factory for user authentication over OpenID4VP.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointFactory
        implements RealmResourceProviderFactory, OID4VPEnvironmentProviderFactory {

    public static final String PROVIDER_ID = "oid4vp-auth";
    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpointFactory.class);

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public RealmResourceProvider create(KeycloakSession session) {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        EventBuilder event = new EventBuilder(realm, session, context.getConnection());
        return new OID4VPUserAuthEndpoint(session, event);
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                logger.debugf("Migrating existing realms to add OpenID4VP user auth flow...");
                KeycloakModelUtils.runJobInTransaction(factory, session ->
                        session.realms().getRealmsStream().forEach(this::migrateRealmIfNecessary)
                );
            } else if (event instanceof RealmModel.RealmPostCreateEvent realmEvent) {
                logger.debugf("Migrating newly created realm to add OpenID4VP user auth flow...");
                RealmModel realm = realmEvent.getCreatedRealm();
                migrateRealmIfNecessary(realm);
            }
        });
    }

    private void migrateRealmIfNecessary(RealmModel realm) {
        if (realm.getFlowByAlias(OID4VP_AUTH_FLOW) == null) {
            logger.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());
            oid4vpAuthenticationFlow(realm);
        } else {
            logger.debugf("OpenID4VP user auth flow already exists for realm '%s'", realm.getName());
        }
    }

    private void oid4vpAuthenticationFlow(final RealmModel realm) {
        AuthenticationFlowModel oid4vpAuthFlow = new AuthenticationFlowModel();

        oid4vpAuthFlow.setAlias(OID4VP_AUTH_FLOW);
        oid4vpAuthFlow.setDescription("Authenticate via OpenID4VP presentations of self-issued identity credentials");
        oid4vpAuthFlow.setProviderId(AuthenticationFlow.BASIC_FLOW);
        oid4vpAuthFlow.setTopLevel(true);
        oid4vpAuthFlow.setBuiltIn(true);
        oid4vpAuthFlow = realm.addAuthenticationFlow(oid4vpAuthFlow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();

        execution.setParentFlow(oid4vpAuthFlow.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
        execution.setAuthenticator(SdJwtAuthenticatorFactory.PROVIDER_ID);
        execution.setPriority(10);
        execution.setAuthenticatorFlow(false);

        realm.addAuthenticatorExecution(execution);
    }

    @Override
    public void close() {
    }
}
