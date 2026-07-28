package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import java.util.LinkedHashMap;
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
     * Realm with an existing OID4VP auth flow.
     */
    public static RealmModel withFlow(String lastApplied) {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW))
                .thenReturn(mock(AuthenticationFlowModel.class));
        when(realm.getAttribute(OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE))
                .thenReturn(lastApplied);
        return realm;
    }

    /**
     * Realm with no flow and an optional stub for {@code addAuthenticationFlow} returning a
     * persisted flow that becomes visible to subsequent lookups.
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
            when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW))
                    .thenReturn(null, persisted);
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
     * Holder for a realm setup that exposes the underlying mocks so tests can add dynamic behavior.
     */
    public record RealmSetup(
            RealmModel realm, AuthenticationExecutionModel execution, AuthenticatorConfigModel config) {}
}
