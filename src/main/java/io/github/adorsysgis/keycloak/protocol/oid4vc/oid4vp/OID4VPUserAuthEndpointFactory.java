package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.OID4VPMigrationManager;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScope;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventBuilder;
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

    private OID4VPConfig pluginConfig;

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
        this.pluginConfig = new OID4VPConfig(config);
        ExtendedCertificateUtils.init(this.pluginConfig);
        ErrorResponseSanitizer.init(this.pluginConfig);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        OID4VPMigrationManager migrationManager = new OID4VPMigrationManager(pluginConfig);

        factory.register(event -> {
            if (event instanceof PostMigrationEvent) {
                logger.debugf("Migrating existing realms to add OpenID4VP user auth flow...");
                KeycloakModelUtils.runJobInTransaction(
                        factory, session -> session.realms().getRealmsStream().forEach(realm -> {
                            migrationManager.migrate(session, realm);
                            logger.debugf("Validating credential scope configurations for realm %s", realm.getName());
                            GuardedCredentialScope.validateRealm(realm);
                        }));
            } else if (event instanceof RealmModel.RealmPostCreateEvent realmEvent) {
                logger.debugf("Migrating newly created realm to add OpenID4VP user auth flow...");
                RealmModel realm = realmEvent.getCreatedRealm();
                migrationManager.migrate(realmEvent.getKeycloakSession(), realm);
            }
        });
    }

    @Override
    public void close() {}
}
