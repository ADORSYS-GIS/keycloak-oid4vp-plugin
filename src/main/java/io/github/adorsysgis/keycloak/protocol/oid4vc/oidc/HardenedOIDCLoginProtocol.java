package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCConfigAttributes;
import org.keycloak.protocol.oidc.OIDCProviderConfig;
import org.keycloak.protocol.oidc.utils.OIDCRedirectUriBuilder;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * OIDC login protocol extension that requires an additional {@code openid4vp://} same-device
 * presentation step before answering the invoking party with the final authorization code, for
 * "presentation during issuance" requests.
 *
 * <p>{@link OIDCLoginProtocol#buildRedirectUri} is the Keycloak-documented extension point for
 * customizing the redirect produced <em>after successful authentication</em> (see
 * <a href="https://github.com/keycloak/keycloak/issues/31086">keycloak/keycloak#31086</a>): it is
 * invoked on every successful OIDC login, whether completed interactively or via SSO. When the
 * finished authentication session targets a presentation-gated OID4VCI credential, control is taken
 * over and the browser is redirected to a freshly generated <em>same-device</em> OpenID4VP
 * presentation instead of back to the client. No Keycloak view is involved.
 *
 * <p>The {@code openid4vp://} same-device link is produced from the {@link OID4VPUserAuthEndpoint}
 * exactly as the login form's cross-/same-device provisioning does, and is bound to the very
 * {@code authSession} whose redirect is being intercepted. Once the wallet presents, the well-known
 * same-device {@code callback} &rarr; {@link OID4VPLoginActionsService} machinery resumes the normal
 * OIDC flow on that same session, records the nested presentation mode, and only then redirects to
 * the invoking party with the final authorization code.
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

    @Override
    public Response buildRedirectUri(
            OIDCRedirectUriBuilder redirectUriBuilder,
            AuthenticationSessionModel authSession,
            UserSessionModel userSession,
            ClientSessionContext clientSessionCtx) {
        if (!PresentationDuringIssuanceSupport.isPresentationGatedCredentialRequestedInSession(authSession)
                // Guard against the loop: only require the presentation once per authorization request. After
                // the same-device presentation completes, the normal OIDC login flow resumes on the *same*
                // authentication session and its redirect must reach the invoking party untouched.
                || PresentationDuringIssuanceSupport.isPresentationTakenOver(authSession)) {
            return super.buildRedirectUri(redirectUriBuilder, authSession, userSession, clientSessionCtx);
        }

        PresentationDuringIssuanceSupport.markPresentationTakenOver(authSession);

        // Capture the final redirect URI to the invoking party (the one that would have been produced
        // for the completed OIDC login) so the same-device callback can simply delay the redirection to
        // it after the presentation completes. The parent auth session no longer exists by callback
        // time, so resuming the OIDC flow to rebuild this redirect is not possible.
        URI savedRedirectUri = redirectUriBuilder.build().getLocation();
        String sameDeviceRequestLink = buildSameDeviceRequestLink(authSession, userSession, savedRedirectUri);
        if (StringUtil.isBlank(sameDeviceRequestLink)) {
            logger.warnf("Could not require a same-device OpenID4VP presentation for a presentation-gated "
                    + "issuance request; resuming normal redirect");
            return super.buildRedirectUri(redirectUriBuilder, authSession, userSession, clientSessionCtx);
        }

        logger.debugf("Requiring a same-device OpenID4VP presentation before issuing the final authorization code");
        logger.debugf("Same device request link is %s", sameDeviceRequestLink);
        return Response.seeOther(URI.create(sameDeviceRequestLink)).build();
    }

    /**
     * Generates a same-device {@code openid4vp://} authorization request link for the authentication
     * profile enforced by the presentation-gated credential requested in this session.
     *
     * <p>The profile is resolved from the credential configuration's
     * {@code vc.presentation_profile_id} client-scope attribute (never from a wallet-selected
     * profile). The OIDC auth session being intercepted no longer exists once the presentation
     * completes, so instead of trying to resume it we carry the already-authenticated user session id
     * and the final redirect URI into the authorization context; the same-device callback then only
     * marks the presentation as verified and redirects to the kept URI.
     *
     * @return the same-device request link, or {@code null} if it could not be produced (e.g. the
     *         requested credential carries no enforced profile)
     */
    private String buildSameDeviceRequestLink(
            AuthenticationSessionModel authSession, UserSessionModel userSession, URI savedRedirectUri) {
        String profileId = PresentationDuringIssuanceSupport.resolveEnforcedProfileId(authSession);
        if (StringUtil.isBlank(profileId)) {
            logger.warnf("Presentation-gated issuance request resolved no enforced OpenID4VP profile; "
                    + "cannot build a same-device presentation");
            return null;
        }

        try {
            session.getContext().setAuthenticationSession(authSession);
            OID4VPUserAuthEndpoint oid4vp = new OID4VPUserAuthEndpoint(session, event);
            String authSessionId = OID4VPUserAuthEndpointBase.getAuthSessionId(authSession);
            OIDCAuthSession oidcAuthSession = new OIDCAuthSession(
                    authSessionId,
                    null,
                    true,
                    userSession.getId(),
                    savedRedirectUri != null ? savedRedirectUri.toString() : null);
            // Bind the already-authenticated session user as the session-identity subject so the
            // OpenID4VP authenticator recovers that user (instead of presented-credential claims) and
            // matches the presented PID against it. The flow runs post-authentication, so the
            // authenticated user is always available here.
            AuthorizationContext authContext = oid4vp.startAuthentication(
                    authSession.getClient().getClientId(),
                    profileId,
                    oidcAuthSession,
                    null,
                    userSession.getUser().getId());
            return authContext.getAuthorizationRequest();
        } catch (RuntimeException e) {
            logger.warnf(e, "Failed to build a same-device OpenID4VP presentation for presentation during issuance");
            return null;
        }
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
            logger.debugf("Removed dpop_jkt client note for client '%s' because DPoP is not enabled",
                    authSession.getClient().getClientId());
        }
    }
}
