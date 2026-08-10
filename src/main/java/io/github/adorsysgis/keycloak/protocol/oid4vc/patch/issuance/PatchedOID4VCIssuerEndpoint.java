package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.keycloak.protocol.oid4vc.utils.CredentialScopeUtils.findCredentialScopeModelByConfigurationId;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.HardenedCredentialScope;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.PresentationDuringIssuanceMode;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
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
 * <p>
 * Additionally enforces "presentation during issuance" (OID4VCI Interactive Authorization): for a
 * credential configuration flagged with {@link HardenedCredentialScope#VC_REQUIRES_PRESENTATION_ATTR}, the
 * credential is only issued when the session carries a verified-presentation marker. This guarantees
 * the authorization code was obtained via a Verifiable Presentation and excludes the pre-authorized
 * code path for such credentials.
 * </p>
 */
public class PatchedOID4VCIssuerEndpoint extends OID4VCIssuerEndpoint {

    private static final Logger logger = Logger.getLogger(PatchedOID4VCIssuerEndpoint.class);

    private final KeycloakSession keycloakSession;

    public PatchedOID4VCIssuerEndpoint(KeycloakSession session) {
        super(session);
        this.keycloakSession = session;
    }

    @Override
    public Response requestCredential(String requestPayload) {
        enforcePresentationDuringIssuance();
        return super.requestCredential(patchWalletRequest(requestPayload));
    }

    /**
     * Rejects issuance of a presentation-gated credential unless the session proves that a Verifiable
     * Presentation was verified. Non-gated credentials and cases the core endpoint rejects on its own
     * are left untouched.
     */
    private void enforcePresentationDuringIssuance() {
        AuthenticationManager.AuthResult authResult = resolveAuthResultWithoutConsumingDPoP();
        if (authResult == null || authResult.token() == null) {
            return; // Let the core endpoint emit the standard invalid-token error.
        }

        String credentialConfigurationId = resolveRequestedCredentialConfigurationId(authResult);
        if (credentialConfigurationId == null) {
            return; // Core endpoint validates authorization_details and rejects if missing.
        }

        ClientModel client = authResult.client();
        RealmModel realm = keycloakSession.getContext().getRealm();
        CredentialScopeModel credentialScope = findCredentialScopeModelByConfigurationId(
                realm, () -> client.getClientScopes(false).values().stream(), credentialConfigurationId);
        if (credentialScope == null) {
            return; // Unknown configuration: core endpoint rejects independently.
        }

        if (isIssuanceGatedWithoutPresentation(credentialScope, authResult.session())) {
            logger.warnf(
                    "Refusing to issue credential '%s': it requires presentation during issuance but the session"
                            + " carries no verified presentation.",
                    credentialConfigurationId);
            throw presentationRequired(credentialConfigurationId);
        }
    }

    /**
     * Reads and verifies the bearer access token WITHOUT triggering DPoP proof validation.
     * <p>
     * The core {@link OID4VCIssuerEndpoint} authenticates the request itself (including the full DPoP
     * check). Since a DPoP proof is single-use, running
     * {@link AppAuthManager.BearerTokenAuthenticator#authenticate()} here as well would consume the
     * proof and make the subsequent core authentication fail with a DPoP replay error. Therefore this
     * gate calls {@link AuthenticationManager#verifyIdentityToken} directly with an empty verifier
     * consumer (no DPoP check), which still validates signature, expiry and revocation and resolves the
     * client/user session, but leaves the DPoP proof untouched for the core endpoint.
     * </p>
     *
     * @return the verified {@link AuthenticationManager.AuthResult}, or {@code null} if no/invalid token
     */
    private AuthenticationManager.AuthResult resolveAuthResultWithoutConsumingDPoP() {
        KeycloakContext context = keycloakSession.getContext();
        String tokenString;
        try {
            tokenString = AppAuthManager.extractAuthorizationHeaderToken(
                    context.getHttpRequest().getHttpHeaders());
        } catch (RuntimeException e) {
            return null; // Malformed/missing Authorization header: let the core endpoint report it.
        }
        if (tokenString == null) {
            return null;
        }
        return AuthenticationManager.verifyIdentityToken(
                keycloakSession,
                context.getRealm(),
                context.getUri(),
                context.getConnection(),
                true, // checkActive
                true, // checkTokenType
                null, // checkAudience
                false, // isCookie
                tokenString,
                context.getHttpRequest().getHttpHeaders(),
                verifier -> {
                    /* intentionally no DPoP verifier: the proof must not be consumed here */
                });
    }

    /**
     * Pure gate decision: whether issuance must be blocked because the credential configuration requires
     * a presentation during issuance but the session carries no verified-presentation marker, or the
     * {@link PresentationDuringIssuanceMode mode} through which it was obtained is not one the
     * credential supports.
     *
     * @param credentialScope the resolved credential configuration (client scope)
     * @param userSession the session bound to the access token, may be {@code null}
     * @return {@code true} if issuance must be refused
     */
    static boolean isIssuanceGatedWithoutPresentation(
            CredentialScopeModel credentialScope, UserSessionModel userSession) {
        if (userSession == null) {
            return true;
        }

        HardenedCredentialScope hardened = HardenedCredentialScope.from(credentialScope);
        if (hardened == null || !hardened.requiresPresentation()) {
            return false;
        }

        String modeValue = userSession.getNote(OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE);
        PresentationDuringIssuanceMode mode = PresentationDuringIssuanceMode.fromWireValue(modeValue);
        return !hardened.supportsPresentationMode(mode);
    }

    private String resolveRequestedCredentialConfigurationId(AuthenticationManager.AuthResult authResult) {
        try {
            @SuppressWarnings("unchecked")
            AuthorizationDetailsProcessor<OID4VCAuthorizationDetail> processor =
                    keycloakSession.getProvider(AuthorizationDetailsProcessor.class, OPENID_CREDENTIAL);
            List<OID4VCAuthorizationDetail> details = processor.getSupportedAuthorizationDetails(
                    authResult.token().getAuthorizationDetails());
            if (details == null || details.isEmpty()) {
                return null;
            }
            return details.getFirst().getCredentialConfigurationId();
        } catch (RuntimeException e) {
            logger.debugf(e, "Could not resolve credential_configuration_id from access token for the issuance gate");
            return null;
        }
    }

    private BadRequestException presentationRequired(String credentialConfigurationId) {
        OAuth2ErrorRepresentation error = new OAuth2ErrorRepresentation(
                "invalid_credential_request",
                "Credential '" + credentialConfigurationId
                        + "' requires a verified presentation during issuance (OID4VCI Interactive Authorization).");
        return new BadRequestException(Response.status(Response.Status.BAD_REQUEST)
                .entity(error)
                .type(MediaType.APPLICATION_JSON_TYPE)
                .build());
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
