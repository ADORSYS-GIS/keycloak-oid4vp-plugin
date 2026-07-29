package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps.Migration_v1_3_0;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

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
        assertUniqueMigrationIds(migrations);
    }

    /**
     * Refuses to construct the manager with duplicate migration ids: resume behaviour would
     * become ambiguous (the manager picks the first match in {@link #indexAfter}) and any
     * stamped marker could refer to either copy. Failing fast at construction is the only
     * place the issue can be diagnosed unambiguously.
     */
    private static void assertUniqueMigrationIds(List<Migration> migrations) {
        Set<String> seen = new HashSet<>(migrations.size());
        for (Migration migration : migrations) {
            if (!seen.add(migration.id())) {
                throw new IllegalArgumentException(
                        "Migration ids must be unique; found duplicate id '" + migration.id() + "'");
            }
        }
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
     *
     * <p>When the manager creates the OID4VP auth flow itself, no individual migrations run and
     * the marker is stamped to the latest migration id directly: the fresh flow is already in
     * the target state. Operators rolling back to a previous flow configuration can simply delete
     * the flow and restart; this also gives operators a way to reset a realm whose recorded
     * marker belongs to a newer or foreign plugin version.
     */
    public void migrate(KeycloakSession session, RealmModel realm) {
        if (realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW) == null) {
            if (config.shouldAutoCreateAuthFlowFor(realm.getName())) {
                ensureOid4vpAuthFlowExists(realm);
                realm.setAttribute(LAST_APPLIED_MIGRATION_ATTRIBUTE, latestMigrationId());
            } else {
                logger.infof(
                        "Skipping migration for realm '%s': no oid4vp auth flow and the realm is not "
                                + "in the managed-realms list",
                        realm.getName());
                return;
            }
        }

        String lastApplied = realm.getAttribute(LAST_APPLIED_MIGRATION_ATTRIBUTE);
        if (StringUtil.isNotBlank(lastApplied) && !isRegisteredMigration(lastApplied)) {
            throw new IllegalStateException(String.format(
                    "Realm '%s' has lastApplied='%s' which does not match any registered migration. "
                            + "Refusing to mutate the realm to avoid masking a newer or foreign plugin "
                            + "version. Downgrading? Consider backing up the current flow configuration "
                            + "and deleting the '%s' flow so Keycloak can create a fresh state on next restart.",
                    realm.getName(), lastApplied, OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW));
        }

        int resumeIndex = indexAfter(migrations, lastApplied);
        if (resumeIndex > 0) {
            logger.debugf(
                    "Skipping %d already-applied migration(s) for realm '%s' (lastApplied=%s)",
                    resumeIndex, realm.getName(), lastApplied);
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

        assertOid4vpAuthFlowIsHealthy(realm);
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

    /**
     * Asserts that the reserved {@link OID4VPUserAuthEndpointBase#OID4VP_AUTH_FLOW oid4vp auth}
     * flow for {@code realm} exists and contains exactly one execution, and that execution
     * references the current {@link OID4VPAuthenticatorFactory#PROVIDER_ID oid4vp-authenticator}.
     */
    void assertOid4vpAuthFlowIsHealthy(RealmModel realm) {
        AuthenticationFlowModel flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            throw new IllegalStateException(String.format(
                    "Authentication flow '%s' is expected to exist in realm '%s' but is missing. "
                            + "Refusing to start.",
                    OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW, realm.getName()));
        }

        List<AuthenticationExecutionModel> executions = realm.getAuthenticationExecutionsStream(flow.getId())
                .toList();

        boolean exactlyOneOid4vpAuthenticator = executions.size() == 1
                && OID4VPAuthenticatorFactory.PROVIDER_ID.equals(executions.getFirst().getAuthenticator());

        if (!exactlyOneOid4vpAuthenticator) {
            String found = executions.stream()
                    .map(AuthenticationExecutionModel::getAuthenticator)
                    .collect(Collectors.joining(", ", "[", "]"));

            throw new IllegalStateException(String.format(
                    "Authentication flow '%s' in realm '%s' is not in the expected state: it must "
                            + "contain exactly one execution with authenticator '%s', but found %d "
                            + "execution(s) with authenticator(s) %s. Refusing to start. "
                    + "Last resort: consider backing up the current flow configuration "
                    + "and deleting the flow so Keycloak can create a fresh state on next restart.",
                    OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW,
                    realm.getName(),
                    OID4VPAuthenticatorFactory.PROVIDER_ID,
                    executions.size(),
                    found));
        }
    }

    /**
     * @return the id of the last migration registered with this manager,
     *         or {@code null} when no migrations are registered.
     */
    private String latestMigrationId() {
        return migrations.isEmpty() ? null : migrations.getLast().id();
    }

    /**
     * @return {@code true} when {@code id} matches the id of a registered {@link Migration}.
     */
    private boolean isRegisteredMigration(String id) {
        return migrations.stream()
                .anyMatch(migration -> Objects.equals(migration.id(), id));
    }
}
