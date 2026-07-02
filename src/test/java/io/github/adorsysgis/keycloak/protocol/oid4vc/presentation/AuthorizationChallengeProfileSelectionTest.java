package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the authoritative profile selection at the Authorization Challenge Endpoint: a profile
 * mandated by the requested credential (presentation during issuance) must take precedence over any
 * client-supplied {@code profile_id} so the identity match cannot be bypassed.
 */
class AuthorizationChallengeProfileSelectionTest {

    @Test
    @DisplayName("enforced profile overrides the client-supplied profile_id")
    void enforcedProfileOverridesRequested() {
        assertEquals(
                "stb-issuance", AuthorizationChallengeEndpoint.effectiveProfileId("attacker-profile", "stb-issuance"));
    }

    @Test
    @DisplayName("enforced profile is used even when the client supplied none")
    void enforcedProfileUsedWhenRequestedBlank() {
        assertEquals("stb-issuance", AuthorizationChallengeEndpoint.effectiveProfileId(null, "stb-issuance"));
    }

    @Test
    @DisplayName("client-supplied profile_id is used when no profile is enforced")
    void requestedProfileUsedWhenNoneEnforced() {
        assertEquals("login", AuthorizationChallengeEndpoint.effectiveProfileId("login", null));
        assertEquals("login", AuthorizationChallengeEndpoint.effectiveProfileId("login", "  "));
    }

    @Test
    @DisplayName("no profile at all resolves to null (default profile downstream)")
    void nullWhenNeitherPresent() {
        assertNull(AuthorizationChallengeEndpoint.effectiveProfileId(null, null));
    }
}
