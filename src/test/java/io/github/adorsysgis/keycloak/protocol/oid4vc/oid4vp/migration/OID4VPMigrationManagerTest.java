package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withExecutions;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withFlow;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withoutFlow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps.Migration_v1_3_0;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

class OID4VPMigrationManagerTest {

    private static OID4VPConfig defaultConfig() {
        return new OID4VPConfig(mock(Config.Scope.class));
    }

    private static OID4VPConfig configWithRealms(String... realms) {
        Config.Scope scope = mock(Config.Scope.class);
        when(scope.get(OID4VPConfig.MANAGED_REALMS_CONFIG)).thenReturn(String.join(",", realms));
        return new OID4VPConfig(scope);
    }

    private static void runMigrations(RealmModel realm, Migration... migrations) {
        runMigrations(defaultConfig(), realm, migrations);
    }

    private static void runMigrations(OID4VPConfig config, RealmModel realm, Migration... migrations) {
        new OID4VPMigrationManager(config, List.of(migrations)).migrate(mock(KeycloakSession.class), realm);
    }

    @Test
    void shouldRunAllMigrationsFromStartInOrder() {
        RealmModel realm = withFlow(null);

        List<String> appliedIds = new ArrayList<>();
        runMigrations(
                realm,
                new RecordingMigration("first", appliedIds::add),
                new RecordingMigration("second", appliedIds::add));

        assertEquals(List.of("first", "second"), appliedIds);
    }

    @Test
    void shouldResumeFromFirstMigrationAfterLastApplied() {
        RealmModel realm = withFlow("m1");

        RecordingMigration m1 = new RecordingMigration("m1");
        RecordingMigration m2 = new RecordingMigration("m2");
        RecordingMigration m3 = new RecordingMigration("m3");
        runMigrations(realm, m1, m2, m3);

        assertEquals(0, m1.invocations.get());
        assertEquals(1, m2.invocations.get());
        assertEquals(1, m3.invocations.get());
    }

    @Test
    void shouldSkipAllWhenLastAppliedIsLatestMigration() {
        RealmModel realm = withFlow("m3");

        RecordingMigration m1 = new RecordingMigration("m1");
        RecordingMigration m2 = new RecordingMigration("m2");
        RecordingMigration m3 = new RecordingMigration("m3");
        runMigrations(realm, m1, m2, m3);

        assertEquals(0, m1.invocations.get());
        assertEquals(0, m2.invocations.get());
        assertEquals(0, m3.invocations.get());
    }

    @Test
    void shouldFailClosedWhenLastAppliedIsNonNullAndNotRegistered() {
        RealmModel realm = withFlow("v99.0.0");

        IllegalStateException thrown = assertThrows(
                IllegalStateException.class,
                () -> runMigrations(realm, new RecordingMigration("v1.0.0")));

        assertTrue(
                thrown.getMessage().contains("Realm 'test' has lastApplied='v99.0.0' which does not match any registered migration"));

        // No mutation of the realm: no flow creation, no execution, no marker change.
        verify(realm, never()).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, never()).addAuthenticatorExecution(any(AuthenticationExecutionModel.class));
        verify(realm, never())
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), any(String.class));
    }

    @Test
    void shouldCreateFlowAndStampLatestWhenManagerRecreatesAFlowForARealmWithAnUnknownMarker() {
        RealmModel realm = withoutFlow("test", "v99.0.0", true);

        runMigrations(configWithRealms("test"), realm, new RecordingMigration("v1.0.0"));

        // Flow was created by the manager itself; the fresh flow is in target state so the
        // unknown marker is overridden with the latest migration id rather than triggering
        // fail-closed.
        verify(realm, times(1)).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, times(1))
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), eq("v1.0.0"));
    }

    @Test
    void shouldAbortBatchWhenMigrationThrows() {
        RealmModel realm = withFlow(null);

        RecordingMigration never = new RecordingMigration("never");

        RuntimeException caught = null;
        try {
            new OID4VPMigrationManager(defaultConfig(), List.of(new FailingMigration(), never))
                    .migrate(mock(KeycloakSession.class), realm);
        } catch (RuntimeException e) {
            caught = e;
        }

        assertNotNull(caught);
        assertEquals("boom", caught.getMessage());
        assertEquals(0, never.invocations.get());
        verify(realm, never()).setAttribute(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE, "failing");
    }

    @Test
    void shouldStampLatestMigrationIdAndSkipMigrationsWhenManagerCreatesTheFlow() {
        RealmModel realm = withoutFlow("test", null, true);

        RecordingMigration m1 = new RecordingMigration("m1");
        RecordingMigration m2 = new RecordingMigration("m2");
        RecordingMigration m3 = new RecordingMigration("m3");
        runMigrations(configWithRealms("test"), realm, m1, m2, m3);

        // The fresh flow is already in target state, so no individual migrations run.
        assertEquals(0, m1.invocations.get());
        assertEquals(0, m2.invocations.get());
        assertEquals(0, m3.invocations.get());

        // The flow was created with the current authenticator.
        verify(realm, times(1)).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, times(1))
                .addAuthenticatorExecution(
                        argThat(exec -> OID4VPAuthenticatorFactory.PROVIDER_ID.equals(exec.getAuthenticator())
                                && AuthenticationExecutionModel.Requirement.REQUIRED.equals(exec.getRequirement())
                                && "new-flow-id".equals(exec.getParentFlow())
                                && !exec.isAuthenticatorFlow()));

        // The marker is stamped directly to the latest migration id, giving operators a simple
        // rollback path: delete the flow + restart.
        verify(realm, times(1))
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), eq("m3"));
    }

    @Test
    void shouldSkipMigrationForNonManagedRealmWithoutFlow() {
        RealmModel realm = withoutFlow("production", null, false);

        runMigrations(configWithRealms("test", "dev"), realm);

        verify(realm, never()).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, never())
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), any(String.class));
    }

    @Test
    void shouldRejectFlowsThatAreNotExactlyOneOid4vpAuthenticator() {
        // All-unrelated executions: migration runs, marker is stamped for the migration that
        // succeeded, and the end-of-migrate health check then throws because the flow has no
        // oid4vp-authenticator.
        {
            RecordingMigration migration = new RecordingMigration("m1");
            RealmModel realm = withExecutions(null, "some-other-authenticator", "yet-another-one");
            IllegalStateException thrown = assertThrows(
                    IllegalStateException.class,
                    () -> runMigrations(realm, migration));
            assertNotNull(thrown.getMessage());
            assertTrue(
                    thrown.getMessage().contains(
                            "execution with authenticator '" + OID4VPAuthenticatorFactory.PROVIDER_ID + "'"),
                    "Exception should name the expected authenticator id along with surrounding "
                            + "context, not just the bare id");
            assertTrue(
                    thrown.getMessage().contains("must contain exactly one execution"),
                    "Exception should explain the strict 'exactly one execution' requirement "
                            + "in its full sentence form");
        }

        // Mixed: one oid4vp-authenticator alongside an unrelated one — still rejected because
        // the flow carries more than one execution.
        {
            RecordingMigration migration = new RecordingMigration("m1");
            RealmModel realm = withExecutions(
                    null, "some-other-authenticator", OID4VPAuthenticatorFactory.PROVIDER_ID);
            assertThrows(
                    IllegalStateException.class,
                    () -> runMigrations(realm, migration));
        }

        // Duplicate oid4vp-authenticator executions — rejected as not exactly one.
        {
            RecordingMigration migration = new RecordingMigration("m1");
            RealmModel realm = withExecutions(
                    null,
                    OID4VPAuthenticatorFactory.PROVIDER_ID,
                    OID4VPAuthenticatorFactory.PROVIDER_ID);
            assertThrows(
                    IllegalStateException.class,
                    () -> runMigrations(realm, migration));
        }

        // Legacy-only execution: rejected because the legacy sd-jwt-authenticator has not been
        // normalized by a real Migration_v1_3_0 in this scenario. (In production that
        // migration renames it before the check runs.)
        {
            RecordingMigration migration = new RecordingMigration("m1");
            RealmModel realm = withExecutions(null, Migration_v1_3_0.LEGACY_AUTHENTICATOR);
            assertThrows(
                    IllegalStateException.class,
                    () -> runMigrations(realm, migration));
        }

        // Sanity check: exactly one oid4vp-authenticator passes the health check and the
        // marker is stamped for the migration that ran.
        {
            RecordingMigration migration = new RecordingMigration("m1");
            RealmModel realm = withExecutions(null, OID4VPAuthenticatorFactory.PROVIDER_ID);
            runMigrations(realm, migration);
            assertEquals(1, migration.invocations.get());
            verify(realm, times(1))
                    .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), eq("m1"));
        }
    }

    /** Records invocations and exposes an optional side-effect recorder. */
    private static final class RecordingMigration implements Migration {

        private final String id;
        final AtomicInteger invocations = new AtomicInteger();
        private final Consumer<String> recorder;

        RecordingMigration(String id) {
            this(id, null);
        }

        RecordingMigration(String id, Consumer<String> recorder) {
            this.id = id;
            this.recorder = recorder;
        }

        @Override
        public String id() {
            return id;
        }

        @Override
        public void apply(KeycloakSession session, RealmModel realm) {
            invocations.incrementAndGet();
            if (recorder != null) {
                recorder.accept(id);
            }
        }
    }

    /** Migration that always throws, used to test batch-abort behavior. */
    private static final class FailingMigration implements Migration {

        @Override
        public String id() {
            return "failing";
        }

        @Override
        public void apply(KeycloakSession session, RealmModel realm) {
            throw new RuntimeException("boom");
        }
    }
}
