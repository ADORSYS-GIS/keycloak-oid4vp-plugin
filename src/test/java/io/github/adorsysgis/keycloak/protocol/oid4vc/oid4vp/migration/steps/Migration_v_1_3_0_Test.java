package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.session;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withAuthenticatorConfig;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withSingleOid4vpAuthenticatorConfig;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.withoutFlow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.MockOid4vpRealm.RealmSetup;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;

@SuppressWarnings("JUnitTestClassNamingConvention")
public class Migration_v_1_3_0_Test {

    private static Migration_v1_3_0 migration() {
        return new Migration_v1_3_0();
    }

    @Test
    void shouldApplyAllStepsToLegacyRealmAndBeIdempotent() {
        LinkedHashMap<String, String> configMap = new LinkedHashMap<>(Map.of(
                Migration_v1_3_0.LEGACY_VCT_CONFIG_KEY, "https://legacy.example/vct",
                Migration_v1_3_0.LEGACY_KBJWT_MAX_AGE_CONFIG_KEY, "75"));

        RealmSetup setup = withAuthenticatorConfig(Migration_v1_3_0.LEGACY_AUTHENTICATOR, configMap);
        RealmModel realm = setup.realm();
        AuthenticationExecutionModel execution = setup.execution();
        Map<String, String> liveConfig = setup.config().getConfig();

        // Track the authenticator field so reads after setAuthenticator see the new value.
        AtomicReference<String> currentAuth = new AtomicReference<>(Migration_v1_3_0.LEGACY_AUTHENTICATOR);
        when(execution.getAuthenticator()).thenAnswer(inv -> currentAuth.get());
        doAnswer(inv -> {
                    currentAuth.set(inv.getArgument(0));
                    return null;
                })
                .when(execution)
                .setAuthenticator(any());

        // First run: legacy alias renamed, both config keys renamed, fallback backfilled.
        migration().apply(session(), realm);

        verify(execution).setAuthenticator(Migration_v1_3_0.CURRENT_AUTHENTICATOR);
        assertEquals(
                "https://legacy.example/vct", liveConfig.get(Migration_v1_3_0.CURRENT_CREDENTIAL_TYPES_CONFIG_KEY));
        assertEquals("75", liveConfig.get(Migration_v1_3_0.CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY));
        assertFalse(liveConfig.containsKey(Migration_v1_3_0.LEGACY_VCT_CONFIG_KEY));
        assertFalse(liveConfig.containsKey(Migration_v1_3_0.LEGACY_KBJWT_MAX_AGE_CONFIG_KEY));
        assertEquals(
                Migration_v1_3_0.CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_DEFAULT,
                liveConfig.get(Migration_v1_3_0.CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY));

        // Second run on the same realm: no legacy markers to find, so no further mutations.
        clearInvocations(realm, execution);
        migration().apply(session(), realm);

        verify(realm, never()).updateAuthenticatorExecution(any(AuthenticationExecutionModel.class));
        verify(realm, never()).updateAuthenticatorConfig(any(AuthenticatorConfigModel.class));
        verify(realm, never()).addAuthenticationFlow(any(AuthenticationFlowModel.class));
    }

    @Test
    void shouldSkipAliasRenameWhenFlowMissing() {
        RealmModel realm = withoutFlow();
        migration().apply(session(), realm);
        verify(realm, never()).getAuthenticationExecutionsStream(any());
    }

    @Test
    void shouldPreserveCurrentCredentialTypesWhenBothPresent() {
        RealmModel realm = withSingleOid4vpAuthenticatorConfig(Map.of(
                Migration_v1_3_0.LEGACY_VCT_CONFIG_KEY, "https://legacy.example/identity",
                Migration_v1_3_0.CURRENT_CREDENTIAL_TYPES_CONFIG_KEY, "https://current.example/identity"));

        migration().apply(session(), realm);

        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById("config-id");
        assertEquals(
                "https://current.example/identity",
                config.getConfig().get(Migration_v1_3_0.CURRENT_CREDENTIAL_TYPES_CONFIG_KEY));
        assertFalse(config.getConfig().containsKey(Migration_v1_3_0.LEGACY_VCT_CONFIG_KEY));
    }

    @Test
    void shouldPreserveCurrentHolderBindingMaxAgeWhenBothPresent() {
        RealmModel realm = withSingleOid4vpAuthenticatorConfig(Map.of(
                Migration_v1_3_0.LEGACY_KBJWT_MAX_AGE_CONFIG_KEY, "90",
                Migration_v1_3_0.CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY, "120"));

        migration().apply(session(), realm);

        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById("config-id");
        assertEquals("120", config.getConfig().get(Migration_v1_3_0.CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY));
        assertFalse(config.getConfig().containsKey(Migration_v1_3_0.LEGACY_KBJWT_MAX_AGE_CONFIG_KEY));
    }

    @Test
    void shouldBeNoOpWhenAllKeysAlreadyCurrent() {
        RealmModel realm = withSingleOid4vpAuthenticatorConfig(Map.of(
                Migration_v1_3_0.CURRENT_CREDENTIAL_TYPES_CONFIG_KEY, "https://example.com/identity",
                Migration_v1_3_0.CURRENT_HOLDER_BINDING_PROOF_MAX_AGE_CONFIG_KEY, "60",
                Migration_v1_3_0.CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY, "false"));

        migration().apply(session(), realm);

        verify(realm, never()).updateAuthenticatorConfig(any(AuthenticatorConfigModel.class));
    }

    @Test
    void shouldPreserveOperatorFallbackToIsoSpecValue() {
        RealmModel realm = withSingleOid4vpAuthenticatorConfig(
                Map.of(Migration_v1_3_0.CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY, "true"));

        migration().apply(session(), realm);

        AuthenticatorConfigModel config = realm.getAuthenticatorConfigById("config-id");
        assertEquals(
                "true",
                config.getConfig().get(Migration_v1_3_0.CURRENT_FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG_KEY));
    }
}
