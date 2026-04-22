package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.util.JsonSerialization;

/**
 * Temporary patch: Translates {@code credential_configuration_id} to {@code credential_identifier}
 * in the incoming Wallet Credential Request.
 * <p>
 * Some wallet applications incorrectly send {@code credential_configuration_id} instead of
 * {@code credential_identifier} (which is required if {@code credential_identifiers} are present
 * in the token, see OID4VCI spec section 8.2).
 * </p>
 * <p>
 * Prerequisite: {@code credential_identifier} and {@code credential_configuration_id}
 * must have the same value (Keycloak default when no separate credential_identifier
 * is configured). Only the incoming request is modified – tokens, OfferState,
 * and all security checks remain fully intact.
 * </p>
 */
public class PatchedOID4VCIssuerEndpoint extends OID4VCIssuerEndpoint {

    private static final Logger logger = Logger.getLogger(PatchedOID4VCIssuerEndpoint.class);

    public PatchedOID4VCIssuerEndpoint(KeycloakSession session) {
        super(session);
    }

    @Override
    public Response requestCredential(String requestPayload) {
        return super.requestCredential(patchWalletRequest(requestPayload));
    }

    protected static String patchWalletRequest(String requestPayload) {
        if (requestPayload == null || requestPayload.isBlank()) {
            return requestPayload;
        }
        try {
            CredentialRequest req = JsonSerialization.readValue(requestPayload, CredentialRequest.class);

            if (req.getCredentialIdentifier() != null || req.getCredentialConfigurationId() == null) {
                return requestPayload; // Nothing to do
            }

            String configId = req.getCredentialConfigurationId();
            logger.debugf(
                    "[Patch] Wallet sent credential_configuration_id='%s', copying to credential_identifier", configId);

            req.setCredentialIdentifier(configId);
            req.setCredentialConfigurationId(null);
            return JsonSerialization.writeValueAsString(req);

        } catch (Exception e) {
            logger.warn("[Patch] Failed to patch wallet credential request, forwarding as-is", e);
            return requestPayload;
        }
    }
}
