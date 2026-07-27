package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

/**
 * Guards the JSON round-trip of {@link AuthorizationContext}, which {@code AuthenticationSessionStore}
 * uses to persist the context on the authentication session. In particular the {@code subject_user_id}
 * carrier (brokered offer user for presentation during issuance) must survive serialization so the
 * OpenID4VP authenticator can take the identity from the credential offer instead of the presented PID.
 */
class AuthorizationContextTest {

    @Test
    @DisplayName("subject_user_id survives the session-store JSON round-trip")
    void subjectUserIdRoundTrips() throws Exception {
        AuthorizationContext context = new AuthorizationContext()
                .setTransactionId("tx-1")
                .setProfileId("stb-issuance")
                .setSubjectUserId("brokered-safe-user-id");

        String json = JsonSerialization.writeValueAsString(context);
        AuthorizationContext restored = JsonSerialization.readValue(json, AuthorizationContext.class);

        assertEquals("brokered-safe-user-id", restored.getSubjectUserId());
        assertEquals("stb-issuance", restored.getProfileId());
        assertEquals("tx-1", restored.getTransactionId());
    }

    @Test
    @DisplayName("subject_user_id is omitted when unset (login flow keeps identity from the credential)")
    void subjectUserIdOmittedWhenUnset() throws Exception {
        AuthorizationContext context = new AuthorizationContext().setTransactionId("tx-2");

        String json = JsonSerialization.writeValueAsString(context);
        AuthorizationContext restored = JsonSerialization.readValue(json, AuthorizationContext.class);

        assertNull(restored.getSubjectUserId());
        // NON_NULL inclusion: the field must not appear in the serialized form when unset.
        assertFalse(json.contains("subject_user_id"));
    }
}
