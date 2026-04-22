package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.util.JsonSerialization;

public class PatchedOID4VCIssuerEndpointTest {

    @Test
    public void testPatchWalletRequest() throws Exception {
        // Case 1: wallet sends credential_configuration_id only
        String payload = "{\"credential_configuration_id\": \"my-config\"}";
        String patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);

        CredentialRequest req = JsonSerialization.readValue(patched, CredentialRequest.class);
        assertEquals("my-config", req.getCredentialIdentifier());
        assertNull(req.getCredentialConfigurationId());

        // Case 2: wallet sends both (already correct or following some other logic)
        payload = "{\"credential_configuration_id\": \"my-config\", \"credential_identifier\": \"my-id\"}";
        patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);
        assertEquals(payload, patched);

        // Case 3: wallet sends credential_identifier only (already correct)
        payload = "{\"credential_identifier\": \"my-id\"}";
        patched = PatchedOID4VCIssuerEndpoint.patchWalletRequest(payload);
        assertEquals(payload, patched);

        // Case 4: null/empty
        assertNull(PatchedOID4VCIssuerEndpoint.patchWalletRequest(null));
        assertEquals("", PatchedOID4VCIssuerEndpoint.patchWalletRequest(""));

        // Case 5: invalid JSON (should be forwarded as-is)
        String invalidJson = "{\"invalid\": ";
        assertEquals(invalidJson, PatchedOID4VCIssuerEndpoint.patchWalletRequest(invalidJson));

        // Case 6: whitespace-only payload (should be returned unchanged)
        String whitespace = "   ";
        assertEquals(whitespace, PatchedOID4VCIssuerEndpoint.patchWalletRequest(whitespace));
    }
}
