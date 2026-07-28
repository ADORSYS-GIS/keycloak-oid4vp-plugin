package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps.Migration_v1_3_0;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Orchestrates the realm migrations of this plugin.
 *
 * <p>Each registered {@link Migration} is applied in order against a realm. The manager resumes
 * from the first migration whose {@link Migration#id()} comes after the realm's recorded
 * last-applied migration ID; migrations before that point are skipped. When the realm has never
 * been migrated, every registered migration is applied.
 *
 * <p>The manager first ensures the {@code oid4vp auth} flow exists for every realm in the
 * configured managed-realms list, so migrations always operate against a real flow rather than
 * running as vacuous no-ops.
 */
public final class OID4VPMigrationManager {

    private static final Logger logger = Logger.getLogger(OID4VPMigrationManager.class);

    /**
     * Realm attribute key storing the {@link Migration#id()} of the most recently applied
     * migration. The manager resumes after this ID on the next migration run.
     */
    public static final String LAST_APPLIED_MIGRATION_ATTRIBUTE = "oid4vp.plugin.lastAppliedMigration";

    private final OID4VPConfig config;
    private final List<Migration> migrations;

    public OID4VPMigrationManager(OID4VPConfig config) {
        this(config, loadMigrations());
    }

    public OID4VPMigrationManager(OID4VPConfig config, List<Migration> migrations) {
        this.config = config;
        this.migrations = List.copyOf(migrations);
    }

    /**
     * The default migration registry this plugin runs, in the order they should apply to a realm.
     */
    public static List<Migration> loadMigrations() {
        List<Migration> migrations = new ArrayList<>();
        migrations.add(new Migration_v1_3_0());
        return migrations;
    }

    /**
     * Ensures the OID4VP auth flow exists for managed realms, then runs every registered migration
     * against {@code realm} in order.
     *
     * <p>Each migration is stamped as {@link #LAST_APPLIED_MIGRATION_ATTRIBUTE} immediately after
     * it completes successfully, so a crash or failure mid-batch resumes from the next migration
     * rather than redoing the entire batch. A migration that throws aborts the rest of the batch
     * without recording a partial state beyond what already succeeded.
     */
    public void migrate(KeycloakSession session, RealmModel realm) {
        if (config.shouldAutoCreateAuthFlowFor(realm.getName())) {
            ensureOid4vpAuthFlowExists(realm);
        }

        if (realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW) == null) {
            logger.debugf(
                    "Skipping migration for realm '%s': no oid4vp auth flow and the realm is not "
                            + "in the managed-realms list",
                    realm.getName());
            return;
        }

        String lastApplied = realm.getAttribute(LAST_APPLIED_MIGRATION_ATTRIBUTE);
        int resumeIndex = indexAfter(migrations, lastApplied);
        if (resumeIndex > 0) {
            logger.debugf(
                    "Skipping %d already-applied migration(s) for realm '%s' (lastApplied=%s)",
                    resumeIndex, realm.getName(), lastApplied);
        } else if (lastApplied != null) {
            logger.warnf(
                    "Realm '%s' has lastApplied='%s' which does not match any registered migration; "
                            + "running all migrations from the start",
                    realm.getName(), lastApplied);
        }

        for (int i = resumeIndex; i < migrations.size(); i++) {
            Migration migration = migrations.get(i);
            logger.infof("Applying migration '%s' to realm '%s'", migration.id(), realm.getName());
            try {
                migration.apply(session, realm);
            } catch (RuntimeException e) {
                logger.errorf(
                        e,
                        "Migration '%s' failed for realm '%s'; aborting remaining migrations",
                        migration.id(),
                        realm.getName());
                throw e;
            }
            realm.setAttribute(LAST_APPLIED_MIGRATION_ATTRIBUTE, migration.id());
            logger.infof("Migration '%s' completed for realm '%s'", migration.id(), realm.getName());
        }
    }

    /**
     * Returns the index of the first migration that should run on resume.
     */
    private static int indexAfter(List<Migration> migrations, String lastApplied) {
        if (lastApplied == null) {
            return 0;
        }
        for (int i = 0; i < migrations.size(); i++) {
            if (lastApplied.equals(migrations.get(i).id())) {
                return i + 1;
            }
        }
        return 0;
    }

    /**
     * Creates the {@code oid4vp auth} flow for the realm if it does not already exist.
     */
    private void ensureOid4vpAuthFlowExists(RealmModel realm) {
        if (realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW) != null) {
            logger.debugf("OpenID4VP user auth flow already exists for realm '%s'", realm.getName());
            return;
        }

        logger.infof("Creating default OpenID4VP user auth flow for realm '%s'", realm.getName());

        AuthenticationFlowModel oid4vpAuthFlow = new AuthenticationFlowModel();
        oid4vpAuthFlow.setAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        oid4vpAuthFlow.setDescription("Authenticate via OpenID4VP presentations of identity credentials");
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
}
