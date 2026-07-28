package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withFlow;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withoutFlow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPConfig;
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
    void shouldRunAllMigrationsWhenLastAppliedDoesNotMatchAnyRegistered() {
        RealmModel realm = withFlow("unknown-id-from-older-plugin-version");

        RecordingMigration m1 = new RecordingMigration("m1");
        RecordingMigration m2 = new RecordingMigration("m2");
        runMigrations(realm, m1, m2);

        assertEquals(1, m1.invocations.get());
        assertEquals(1, m2.invocations.get());
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
    void shouldCreateFlowBeforeRunningMigrationsWithCurrentAuthenticator() {
        RealmModel realm = withoutFlow("test", null, true);

        RecordingMigration migration = new RecordingMigration("m3");
        runMigrations(configWithRealms("test"), realm, migration);

        verify(realm, times(1)).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, times(1))
                .addAuthenticatorExecution(
                        argThat(exec -> OID4VPAuthenticatorFactory.PROVIDER_ID.equals(exec.getAuthenticator())
                                && AuthenticationExecutionModel.Requirement.REQUIRED.equals(exec.getRequirement())
                                && "new-flow-id".equals(exec.getParentFlow())
                                && !exec.isAuthenticatorFlow()));

        inOrder(realm)
                .verify(realm)
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), eq("m3"));
        assertEquals(1, migration.invocations.get());
    }

    @Test
    void shouldSkipMigrationForNonManagedRealmWithoutFlow() {
        RealmModel realm = withoutFlow("production", null, false);

        runMigrations(configWithRealms("test", "dev"), realm);

        verify(realm, never()).addAuthenticationFlow(any(AuthenticationFlowModel.class));
        verify(realm, never())
                .setAttribute(eq(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE), any(String.class));
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
