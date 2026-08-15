package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCProviderConfig;
import org.keycloak.sessions.AuthenticationSessionModel;

/** OIDC protocol extension combining DPoP handling with nested issuance authorization. */
public class ExtendedOIDCLoginProtocol extends OIDCLoginProtocol {

    private static final Logger logger = Logger.getLogger(ExtendedOIDCLoginProtocol.class);

    public ExtendedOIDCLoginProtocol(OIDCProviderConfig providerConfig) {
        super(providerConfig);
    }

    /** Prevents an unsolicited DPoP thumbprint from being bound to a non-DPoP client. */
    @Override
    public Response authenticated(
            AuthenticationSessionModel authSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        handleDpopJktForClient(authSession);
        return super.authenticated(authSession, userSession, clientSessionCtx);
    }

    /** Removes an unsolicited DPoP thumbprint from the authorization session. */
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
