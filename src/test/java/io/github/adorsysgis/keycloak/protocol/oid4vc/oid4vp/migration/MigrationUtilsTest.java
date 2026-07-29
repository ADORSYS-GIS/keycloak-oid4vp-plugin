package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withAuthenticatorConfig;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.RealmSetup;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

class MigrationUtilsTest {

    private static final String CONFIG_KEY = "key";

    @Test
    void configsInOid4vpFlowReturnsEmptyListWhenFlowMissing() {
        RealmModel realm = mock(RealmModel.class);
        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(null);

        assertEquals(List.of(), MigrationUtils.configsInOid4vpFlow(realm, "provider-a"));
    }

    @Test
    void configsInOid4vpFlowMatchesExecutionsByAuthenticator() {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        AuthenticatorConfigModel configA = mock(AuthenticatorConfigModel.class);
        AuthenticatorConfigModel configB = mock(AuthenticatorConfigModel.class);

        AuthenticationExecutionModel execA = executionWith("provider-a", "config-a");
        AuthenticationExecutionModel execB = executionWith("provider-b", "config-b");
        AuthenticationExecutionModel execOther = executionWith("provider-c", "config-c");

        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(flow);
        when(flow.getId()).thenReturn("flow-id");
        when(realm.getAuthenticationExecutionsStream("flow-id"))
                .thenAnswer(invocation -> Stream.of(execA, execB, execOther));
        when(realm.getAuthenticatorConfigById("config-a")).thenReturn(configA);
        when(realm.getAuthenticatorConfigById("config-b")).thenReturn(configB);

        List<AuthenticatorConfigModel> configs =
                MigrationUtils.configsInOid4vpFlow(realm, "provider-a", "provider-b");

        assertEquals(List.of(configA, configB), configs);
    }

    @Test
    void configsInOid4vpFlowSkipsExecutionsWithBlankOrMissingConfigId() {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);

        AuthenticationExecutionModel execAttached = executionWith("provider-a", "config-a");
        AuthenticationExecutionModel execNull = executionWith("provider-a", null);
        AuthenticationExecutionModel execBlank = mock(AuthenticationExecutionModel.class);
        when(execBlank.getAuthenticator()).thenReturn("provider-a");
        when(execBlank.getAuthenticatorConfig()).thenReturn("   ");

        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(flow);
        when(flow.getId()).thenReturn("flow-id");
        when(realm.getAuthenticationExecutionsStream("flow-id"))
                .thenAnswer(invocation -> Stream.of(execAttached, execNull, execBlank));
        when(realm.getAuthenticatorConfigById("config-a")).thenReturn(config);

        assertEquals(List.of(config), MigrationUtils.configsInOid4vpFlow(realm, "provider-a"));
    }

    @Test
    void configsInOid4vpFlowRejectsDuplicateProviderIds() {
        RealmModel realm = mock(RealmModel.class);
        AuthenticationFlowModel flow = mock(AuthenticationFlowModel.class);
        when(realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW)).thenReturn(flow);
        when(flow.getId()).thenReturn("flow-id");
        when(realm.getAuthenticationExecutionsStream("flow-id"))
                .thenAnswer(invocation -> Stream.empty());

        // Set.of throws IllegalArgumentException on duplicate elements; a duplicate provider id
        // here is almost certainly a caller bug, and silently dropping it would mask the mistake.
        assertThrows(
                IllegalArgumentException.class,
                () -> MigrationUtils.configsInOid4vpFlow(realm, "provider-a", "provider-a"),
                "Duplicate provider ids must fail fast rather than be silently deduped");
    }

    @Test
    void putCreatesConfigMapWhenAbsentAndReplacesWhenPresent() {
        // Simulate a config model that starts with a null map and persists whatever the
        // production code writes via setConfig.
        AuthenticatorConfigModel absent = mock(AuthenticatorConfigModel.class);
        AtomicReference<Map<String, String>> stored = new AtomicReference<>(null);
        when(absent.getConfig()).thenAnswer(invocation -> stored.get());
        doAnswer(invocation -> {
                    stored.set(invocation.getArgument(0));
                    return null;
                })
                .when(absent)
                .setConfig(any(Map.class));

        MigrationUtils.put(absent, CONFIG_KEY, "first");
        assertEquals("first", absent.getConfig().get(CONFIG_KEY));

        // When the config map is already present, put must mutate the existing map.
        Map<String, String> existing = new LinkedHashMap<>(Map.of(CONFIG_KEY, "old"));
        AuthenticatorConfigModel present = mock(AuthenticatorConfigModel.class);
        when(present.getConfig()).thenReturn(existing);
        MigrationUtils.put(present, CONFIG_KEY, "new");
        assertEquals("new", existing.get(CONFIG_KEY));
    }

    @Test
    void removeAndContainsOperateOnTheConfigMap() {
        Map<String, String> map = new LinkedHashMap<>(Map.of(CONFIG_KEY, "v"));
        AuthenticatorConfigModel config = mock(AuthenticatorConfigModel.class);
        when(config.getConfig()).thenReturn(map);

        assertTrue(MigrationUtils.contains(config, CONFIG_KEY));
        assertEquals("v", MigrationUtils.get(config, CONFIG_KEY));

        MigrationUtils.remove(config, CONFIG_KEY);
        assertFalse(MigrationUtils.contains(config, CONFIG_KEY));
        assertNull(MigrationUtils.get(config, CONFIG_KEY));

        // No-op when the config map itself is null.
        AuthenticatorConfigModel empty = mock(AuthenticatorConfigModel.class);
        when(empty.getConfig()).thenReturn(null);
        MigrationUtils.remove(empty, CONFIG_KEY);
        assertFalse(MigrationUtils.contains(empty, CONFIG_KEY));
        assertNull(MigrationUtils.get(empty, CONFIG_KEY));
    }

    @Test
    void renameKeyCopiesLegacyValueAndRemovesLegacyKey() {
        Map<String, String> configMap = new LinkedHashMap<>(Map.of("legacy", "v"));
        RealmSetup setup = withAuthenticatorConfig("provider-x", Map.of());
        AuthenticatorConfigModel config = setup.config();
        when(config.getConfig()).thenReturn(configMap);
        RealmModel realm = setup.realm();

        int renamed = MigrationUtils.renameKey(realm, "legacy", "fresh", "provider-x");

        assertEquals(1, renamed);
        assertEquals("v", configMap.get("fresh"));
        assertFalse(configMap.containsKey("legacy"));
    }

    @Test
    void renameKeyLeavesExistingNewKeyUntouched() {
        Map<String, String> configMap = new LinkedHashMap<>(Map.of(
                "legacy", "old-legacy",
                "fresh", "current"));
        RealmSetup setup = withAuthenticatorConfig("provider-x", Map.of());
        AuthenticatorConfigModel config = setup.config();
        when(config.getConfig()).thenReturn(configMap);
        RealmModel realm = setup.realm();

        int renamed = MigrationUtils.renameKey(realm, "legacy", "fresh", "provider-x");

        assertEquals(1, renamed);
        assertEquals("current", configMap.get("fresh"), "Existing new-key value must not be overwritten");
        assertFalse(configMap.containsKey("legacy"));
    }

    @Test
    void renameKeyIsNoOpWhenConfigListIsEmpty() {
        // Sanity check: when no execution matches the supplied provider ids, renameKey is a
        // silent no-op. This matters because migrations can call renameKey with the legacy
        // AND current provider id on a flow that has been migrated already.
        RealmSetup setup = withAuthenticatorConfig(OID4VPAuthenticatorFactory.PROVIDER_ID, Map.of());
        RealmModel realm = setup.realm();

        int renamed = MigrationUtils.renameKey(realm, "legacy", "fresh", "missing-provider");

        assertEquals(0, renamed);
    }

    private static AuthenticationExecutionModel executionWith(String authenticator, String configId) {
        AuthenticationExecutionModel execution = mock(AuthenticationExecutionModel.class);
        when(execution.getAuthenticator()).thenReturn(authenticator);
        when(execution.getAuthenticatorConfig()).thenReturn(configId);
        return execution;
    }
}
