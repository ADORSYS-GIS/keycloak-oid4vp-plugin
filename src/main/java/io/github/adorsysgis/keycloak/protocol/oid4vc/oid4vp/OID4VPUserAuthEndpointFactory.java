package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
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

/**
 * Factory for user authentication over OpenID4VP.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointFactory implements RealmResourceProviderFactory, OID4VPEnvironmentProviderFactory {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpointFactory.class);

    public static final String PROVIDER_ID = "oid4vp-auth";

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
        OID4VPConfig pluginConfig = new OID4VPConfig(config);
        ExtendedCertificateUtils.init(pluginConfig);
        ErrorResponseSanitizer.init(pluginConfig);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                logger.debugf("Migrating existing realms to add OpenID4VP user auth flow...");
                KeycloakModelUtils.runJobInTransaction(
                        factory, session -> session.realms().getRealmsStream().forEach(this::migrateRealmIfNecessary));
            } else if (event instanceof RealmModel.RealmPostCreateEvent realmEvent) {
                logger.debugf("Migrating newly created realm to add OpenID4VP user auth flow...");
                RealmModel realm = realmEvent.getCreatedRealm();
                migrateRealmIfNecessary(realm);
            }
        });
    }

    private void migrateRealmIfNecessary(RealmModel realm) {
        AuthenticationFlowModel oid4vpAuthFlow = realm.getFlowByAlias(OID4VP_AUTH_FLOW);
        if (oid4vpAuthFlow == null) {
            logger.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());
            oid4vpAuthenticationFlow(realm);
            return;
        }

        logger.debugf("OpenID4VP user auth flow already exists for realm '%s'", realm.getName());

        boolean hasExpectedAuthenticator = realm.getAuthenticationExecutionsStream(oid4vpAuthFlow.getId())
                .map(AuthenticationExecutionModel::getAuthenticator)
                .anyMatch(OID4VPAuthenticatorFactory.PROVIDER_ID::equals);

        if (!hasExpectedAuthenticator) {
            throw new IllegalStateException(String.format(
                    "Authentication flow '%s' already exists in realm '%s' but does not contain the expected "
                            + "OpenID4VP authenticator '%s'. Refusing to start. Consider backing up the current "
                            + "flow configuration and removing it so Keycloak can create a new one on next restart.",
                    OID4VP_AUTH_FLOW, realm.getName(), OID4VPAuthenticatorFactory.PROVIDER_ID));
        }
    }

    private void oid4vpAuthenticationFlow(final RealmModel realm) {
        AuthenticationFlowModel oid4vpAuthFlow = new AuthenticationFlowModel();

        oid4vpAuthFlow.setAlias(OID4VP_AUTH_FLOW);
        oid4vpAuthFlow.setDescription("Authenticate via OpenID4VP presentations of self-issued identity credentials");
        oid4vpAuthFlow.setProviderId(AuthenticationFlow.BASIC_FLOW);
        oid4vpAuthFlow.setTopLevel(true);
        oid4vpAuthFlow.setBuiltIn(false);
        oid4vpAuthFlow = realm.addAuthenticationFlow(oid4vpAuthFlow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();

        execution.setParentFlow(oid4vpAuthFlow.getId());
        execution.setRequirement(AuthenticationExecutionModel.Requirement.REQUIRED);
        execution.setAuthenticator(OID4VPAuthenticatorFactory.PROVIDER_ID);
        execution.setPriority(10);
        execution.setAuthenticatorFlow(false);

        realm.addAuthenticatorExecution(execution);
    }

    @Override
    public void close() {}
}
