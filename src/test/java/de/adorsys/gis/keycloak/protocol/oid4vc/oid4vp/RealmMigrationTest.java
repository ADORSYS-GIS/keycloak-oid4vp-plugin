package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * Testing realm migration for adding OpenID4VP user auth flow.
 */
public class RealmMigrationTest {

    @Nested
    class TestMigrationOfNewRealms extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            // Test containers imports this realm.
            // Imported realms are treated as new realms
            return TEST_REALM_V2_NAME;
        }

        @Test
        public void shouldMigrateNewRealms() {
            assertDoesNotThrow(this::requestAuthorizationRequest);
        }
    }
}
