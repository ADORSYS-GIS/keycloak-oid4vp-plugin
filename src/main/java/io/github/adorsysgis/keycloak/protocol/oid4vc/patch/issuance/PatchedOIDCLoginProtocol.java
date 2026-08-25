package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.PresentationDuringIssuanceService;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCProviderConfig;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * OIDC protocol customizations required by this plugin:
 *
 * <ul>
 *   <li>remove an unsupported {@code dpop_jkt} client note when DPoP is disabled (see
 *       <a href="https://github.com/keycloak/keycloak/issues/51573">Keycloak issue #51573</a>),</li>
 *   <li>force reauthentication when the parent OIDC transaction requires nested presentation during
 *       issuance, preventing an existing login from bypassing that presentation step.</li>
 * </ul>
 */
public class PatchedOIDCLoginProtocol extends OIDCLoginProtocol {

    private static final Logger logger = Logger.getLogger(PatchedOIDCLoginProtocol.class);

    public PatchedOIDCLoginProtocol(OIDCProviderConfig providerConfig) {
        super(providerConfig);
    }

    @Override
    public Response authenticated(
            AuthenticationSessionModel authSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        handleDpopJktForClient(authSession);
        return super.authenticated(authSession, userSession, clientSessionCtx);
    }

    @Override
    public boolean requireReauthentication(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        if (new PresentationDuringIssuanceService(session, authSession).requiresNestedPresentationDuringIssuance()) {
            return true;
        }

        return super.requireReauthentication(userSession, authSession);
    }

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
