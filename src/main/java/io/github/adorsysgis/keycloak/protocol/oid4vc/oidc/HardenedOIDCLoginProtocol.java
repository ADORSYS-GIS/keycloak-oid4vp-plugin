package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
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

        String sameDeviceRequestLink = buildSameDeviceRequestLink(authSession, userSession);
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
     * profile). The same-device request is bound to the OIDC {@code authSession} being intercepted and
     * to the {@code oid4vp-auth-login} action so the resumed redirect completes this OIDC flow.
     *
     * @return the same-device request link, or {@code null} if it could not be produced (e.g. the
     *         requested credential carries no enforced profile)
     */
    private String buildSameDeviceRequestLink(AuthenticationSessionModel authSession, UserSessionModel userSession) {
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
            OIDCAuthSession oidcAuthSession = new OIDCAuthSession(authSessionId, buildOid4vpLoginActionUrl(), true);
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
     * URL where the same-device OID4VP flow resumes the OIDC login ({@link OID4VPLoginActionsService}),
     * mirroring {@link OID4VPUserAuthBean#getLoginActionUrl()}.
     */
    private String buildOid4vpLoginActionUrl() {
        return UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPLoginActionsServiceFactory.PROVIDER_ID)
                .path(OID4VPLoginActionsService.OID4VP_AUTH_LOGIN_PATH)
                .build(realm.getName())
                .toString();
    }
}
