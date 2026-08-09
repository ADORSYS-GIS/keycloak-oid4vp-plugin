package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCProviderConfig;
import org.keycloak.protocol.oidc.utils.OIDCRedirectUriBuilder;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * OIDC login protocol that derails the naturally constructed redirect to the invoking party's
 * {@code redirect_uri} for "presentation during issuance" requests.
 *
 * <p>{@link OIDCLoginProtocol#buildRedirectUri} is the Keycloak-documented extension point for
 * customizing the redirect produced <em>after successful authentication</em> (see
 * <a href="https://github.com/keycloak/keycloak/issues/31086">keycloak/keycloak#31086</a>): it is
 * invoked on every successful OIDC login, whether completed interactively or via SSO. When the
 * finished authentication session targets a presentation-gated OID4VCI credential, control is taken
 * over and the browser is sent elsewhere (currently a fixed interception target) instead of back to
 * the client.
 */
public class PatchedOIDCLoginProtocol extends OIDCLoginProtocol {

    private static final Logger logger = Logger.getLogger(PatchedOIDCLoginProtocol.class);

    /** Interception target for this spike: replaced by the same-device OpenID4VP presentation later. */
    public static final String INTERCEPT_REDIRECT_URL = "https://google.com";

    public PatchedOIDCLoginProtocol(OIDCProviderConfig providerConfig) {
        super(providerConfig);
    }

    @Override
    public Response buildRedirectUri(
            OIDCRedirectUriBuilder redirectUriBuilder,
            AuthenticationSessionModel authSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        if (PresentationDuringIssuanceSupport.isPresentationGatedCredentialRequestedInSession(authSession)) {
            logger.infof(
                    "Successful authentication completed for a presentation-gated issuance request; "
                            + "redirecting to %s instead of the invoking party's redirect_uri",
                    INTERCEPT_REDIRECT_URL);
            return Response.seeOther(URI.create(INTERCEPT_REDIRECT_URL)).build();
        }
        return super.buildRedirectUri(redirectUriBuilder, authSession, userSession, clientSessionCtx);
    }
}