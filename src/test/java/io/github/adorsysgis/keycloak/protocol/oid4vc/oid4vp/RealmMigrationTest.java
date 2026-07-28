package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.OID4VPMigrationManager.LAST_APPLIED_MIGRATION_ATTRIBUTE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps.Migration_v1_3_0.LEGACY_KBJWT_MAX_AGE_CONFIG_KEY;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.steps.Migration_v1_3_0.LEGACY_VCT_CONFIG_KEY;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.migration.OID4VPMigrationManager;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

/**
 * Integration tests for realm migration.
 */
public class RealmMigrationTest {

    private static final String LATEST_MIGRATION_ID =
            OID4VPMigrationManager.loadMigrations().getLast().id();

    @Nested
    class TestMigrationOfNewRealms extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            return TEST_REALM_V2_NAME;
        }

        @Test
        public void shouldMigrateNewRealms() {
            assertRealmWasMigrated(getActiveTestRealmResource());
            assertDoesNotThrow(this::requestAuthorizationRequest);
        }
    }

    @Nested
    class TestMigrationOfLegacyRealm extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            return TEST_REALM_LEGACY_V1_2_6_NAME;
        }

        @Test
        public void shouldMigrateLegacyRealmAndStartAuthorizationRequest() {
            String legacyRealmConfigId = "sd-jwt-auth-config-id";
            RealmResource realmResource = getActiveTestRealmResource();
            assertRealmWasMigrated(realmResource);
            assertDoesNotThrow(this::requestAuthorizationRequest);

            // Authenticator alias renamed from legacy to current

            List<AuthenticationExecutionInfoRepresentation> executions =
                    realmResource.flows().getExecutions(OID4VP_AUTH_FLOW);

            assertEquals(1, executions.size());
            assertEquals(
                    OID4VPAuthenticatorFactory.PROVIDER_ID,
                    executions.getFirst().getProviderId(),
                    "Execution must reference the current authenticator after migration");

            // Config keys renamed and legacy keys removed

            AuthenticatorConfigRepresentation config =
                    realmResource.flows().getAuthenticatorConfig(legacyRealmConfigId);
            Map<String, String> configMap = config.getConfig();

            assertEquals(
                    "https://credentials.example.com/identity_credential,https://example.com/vct-alt",
                    configMap.get(OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG),
                    "Legacy 'vct' value must have been copied to 'credentialTypes'");
            assertEquals(
                    "60",
                    configMap.get(OID4VPAuthenticatorFactory.HOLDER_BINDING_PROOF_MAX_AGE_CONFIG),
                    "Legacy 'kbJwtMaxAge' value must have been copied to 'holderBindingProofMaxAge'");

            assertFalse(configMap.containsKey(LEGACY_VCT_CONFIG_KEY), "Legacy 'vct' key must be removed");
            assertFalse(
                    configMap.containsKey(LEGACY_KBJWT_MAX_AGE_CONFIG_KEY), "Legacy 'kbJwtMaxAge' key must be removed");
        }
    }

    private static void assertRealmWasMigrated(RealmResource realmResource) {
        RealmRepresentation realm = realmResource.toRepresentation();
        Map<String, String> attributes =
                Optional.ofNullable(realm.getAttributes()).orElseGet(Map::of);
        assertEquals(
                LATEST_MIGRATION_ID,
                attributes.get(LAST_APPLIED_MIGRATION_ATTRIBUTE),
                "Migration manager must have stamped the last-applied marker after startup");
    }
}
