package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCProviderConfig;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * OIDC login protocol extension used alongside the {@link GatedOIDCAuthorizationEndpoint}.
 *
 * <p>The OpenID4VP "presentation during issuance" interception happens <em>before</em> the browser
 * login flow (see {@link GatedOIDCAuthorizationEndpoint}), so the regular OIDC redirect produced
 * after successful authentication needs no extra derailing here: after the presentation completes
 * and the {@link OID4VPLoginActionsService} resumes the flow, {@code buildRedirectUri} redirects
 * straight back to the invoking party with the final authorization code.
 *
 * <p>Only the DPoP hardening remains overridden.
 */
public class HardenedOIDCLoginProtocol extends OIDCLoginProtocol {

    private static final Logger logger = Logger.getLogger(HardenedOIDCLoginProtocol.class);

    public HardenedOIDCLoginProtocol(OIDCProviderConfig providerConfig) {
        super(providerConfig);
    }

    /**
     * A wallet may send {@code dpop_jkt} in the authorization request even when the client is not
     * configured for DPoP (see keycloak/keycloak#51573). Keycloak reads the {@code dpop_jkt} client
     * note and binds it into the issued authorization code, then validates the DPoP thumbprint at the
     * token endpoint unconditionally, which breaks token exchange for non-DPoP clients.
     */
    @Override
    public Response authenticated(
            AuthenticationSessionModel authSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        handleDpopJktForClient(authSession);
        return super.authenticated(authSession, userSession, clientSessionCtx);
    }

    /**
     * Removes the {@code dpop_jkt} client note when the client is not configured for DPoP, so the value
     * is not bound to the issued authorization code (keycloak/keycloak#51573).
     */
    private void handleDpopJktForClient(AuthenticationSessionModel authSession) {
        if (authSession.getClientNote(OIDCLoginProtocol.DPOP_JKT) == null) {
            return;
        }
        boolean dpopEnabled = Boolean.parseBoolean(
                authSession.getClient().getAttribute(OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS));
        if (!dpopEnabled) {
            authSession.removeClientNote(OIDCLoginProtocol.DPOP_JKT);
            logger.debugf(
                    "Removed dpop_jkt client note for client '%s' because DPoP is not enabled",
                    authSession.getClient().getClientId());
        }
    }
}
