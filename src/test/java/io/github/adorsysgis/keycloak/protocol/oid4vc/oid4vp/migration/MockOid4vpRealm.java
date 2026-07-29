package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Test helpers for building up mocked {@link RealmModel} instances for migration tests.
 */
public final class MockOid4vpRealm {

    private MockOid4vpRealm() {}

    public static KeycloakSession session() {
        return mock(KeycloakSession.class);
    }

    /**
     * Realm with no OID4VP auth flow.
     */
    public static RealmModel withoutFlow() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(null);
        return realm;
    }

    /**
     * Realm with an existing OID4VP auth flow carrying a single healthy execution
     * ({@link OID4VPAuthenticatorFactory#PROVIDER_ID}). This is the realistic default for tests
     * that do not care about the flow's execution contents.
     */
    public static RealmModel withFlow(String lastApplied) {
        return withExecutions(lastApplied, OID4VPAuthenticatorFactory.PROVIDER_ID);
    }

    /**
     * Realm with no flow and an optional stub for {@code addAuthenticationFlow} returning a
     * persisted flow that becomes visible to subsequent lookups. When {@code stubCreation} is
     * true the persisted flow is also pre-populated with a single healthy
     * {@link OID4VPAuthenticatorFactory#PROVIDER_ID} execution, so the post-migration health
     * check passes.
     */
    public static RealmModel withoutFlow(String name, String lastApplied, boolean stubCreation) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn(name);
        when(realm.getAttribute(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE))
                .thenReturn(lastApplied);
        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(null);

        if (stubCreation) {
            AuthenticationFlowModel persisted = mock(AuthenticationFlowModel.class);
            when(persisted.getId()).thenReturn("new-flow-id");
            when(realm.addAuthenticationFlow(any(AuthenticationFlowModel.class)))
                    .thenReturn(persisted);
            // The flow is reported as missing for the first two lookups (the manager's own
            // existence check + the existence check inside ensureOid4vpAuthFlowExists), then
            // becomes visible after addAuthenticationFlow has been called.
            when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW))
                    .thenReturn(null, null, persisted);

            AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
            when(execution.getAuthenticator()).thenReturn(OID4VPAuthenticatorFactory.PROVIDER_ID);
            lenient()
                    .when(realm.getAuthenticationExecutionsStream("new-flow-id"))
                    .thenAnswer(invocation -> Stream.of(execution));
        }

        return realm;
    }

    /**
     * Convenience: {@link #withAuthenticatorConfig} using the current authenticator.
     */
    public static RealmModel withSingleOid4vpAuthenticatorConfig(Map<String, String> configEntries) {
        return withAuthenticatorConfig(OID4VPAuthenticatorFactory.PROVIDER_ID, configEntries)
                .realm();
    }

    /**
     * Builds a realm with a flow containing a single execution pointing to the given authenticator,
     * plus the supplied authenticator config.
     */
    public static RealmSetup withAuthenticatorConfig(String authenticatorId, Map<String, String> configEntries) {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);

        lenient()
                .when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW))
                .thenReturn(flow);
        lenient().when(flow.getId()).thenReturn("flow-id");
        lenient()
                .when(realm.getAuthenticationExecutionsStream("flow-id"))
                .thenAnswer(invocation -> Stream.of(execution));
        lenient().when(execution.getAuthenticator()).thenReturn(authenticatorId);
        lenient().when(execution.getAuthenticatorConfig()).thenReturn("config-id");
        lenient().when(realm.getAuthenticatorConfigById("config-id")).thenReturn(config);
        lenient().when(config.getConfig()).thenReturn(new LinkedHashMap<>(configEntries));

        return new RealmSetup(realm, execution, config);
    }

    /**
     * Builds a realm whose {@code oid4vp auth} flow exposes a stream of executions whose
     * {@link AuthenticationExecutionModel#getAuthenticator()} values match the supplied
     * authenticator ids, in order. Useful for asserting how the manager reacts to flows that
     * contain unknown or mixed execution sets.
     */
    public static RealmModel withExecutions(String lastApplied, String... authenticatorIds) {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        List<AuthenticationExecutionModel> executions = new ArrayList<>(authenticatorIds.length);
        for (String authenticatorId : authenticatorIds) {
            AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
            when(execution.getAuthenticator()).thenReturn(authenticatorId);
            executions.add(execution);
        }

        lenient()
                .when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW))
                .thenReturn(flow);
        lenient().when(flow.getId()).thenReturn("flow-id");
        lenient()
                .when(realm.getAuthenticationExecutionsStream("flow-id"))
                .thenAnswer(invocation -> executions.stream());
        lenient()
                .when(realm.getAttribute(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE))
                .thenReturn(lastApplied);

        return realm;
    }

    /**
     * Holder for a realm setup that exposes the underlying mocks so tests can add dynamic behavior.
     */
    public record RealmSetup(
            RealmModel realm, AuthenticationExecutionModel execution, AuthenticatorConfigModel config) {}
}
