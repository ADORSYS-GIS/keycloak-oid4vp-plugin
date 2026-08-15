package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferStorage;
import org.keycloak.protocol.oid4vc.model.IssuerState;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.utils.StringUtil;

/**
 * OIDC Authorization Endpoint that makes an OpenID4VP presentation <em>replace</em> the
 * username/password login for "presentation during issuance" requests (the
 * {@code nested_oid4vp_flow} mode).
 *
 * <p>The stock {@link AuthorizationEndpoint} runs the browser authentication flow for every OIDC
 * authorization request, which first shows the login form (username/password). This subclass,
 * instead, intercepts in {@link #handleBrowserAuthenticationRequest} — the single entry point
 * shared by the GET/POST authorization paths and PAR — and, when the request targets a
 * presentation-gated OID4VCI credential, skips the login form entirely and redirects the browser
 * to a freshly generated <em>same-device</em> OpenID4VP presentation. No username/password is
 * ever asked: the presentation <em>is</em> the authentication.
 *
 * <p>The same-device request is bound to the real OIDC authentication session (the one created by
 * the authorization endpoint) and its {@code login_action_url} points back to the
 * {@link OID4VPLoginActionsService}. When the wallet presents successfully, the well-known
 * same-device {@code callback} &rarr; {@code /oid4vp-auth-login} machinery attaches the user
 * recovered from the presented credential to that OIDC session and resumes the normal
 * {@link org.keycloak.protocol.oidc.OIDCLoginProtocol} flow, which then redirects to the invoking
 * party with the final authorization code. The flow therefore ends in {@code LoginActions} exactly
 * like the regular same-device user-authentication flow.
 *
 * <p>Because the interception happens before the browser flow starts, the same OIDC authentication
 * session survives presentation and is resumed afterwards; no "delayed redirection" is needed.
 */
public class GatedOIDCAuthorizationEndpoint extends AuthorizationEndpoint {

    private static final Logger logger = Logger.getLogger(GatedOIDCAuthorizationEndpoint.class);

    private final KeycloakSession session;
    private final EventBuilder event;
    private final RealmModel realm;

    public GatedOIDCAuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.session = session;
        this.event = event;
        this.realm = session.getContext().getRealm();
    }

    @Override
    protected Response handleBrowserAuthenticationRequest(
            AuthenticationSessionModel authSession,
            LoginProtocol protocol,
            boolean isPassive,
            boolean redirectToAuthentication) {
        // Passive (prompt=none) requests should not trigger an interactive presentation.
        if (!isPassive && PresentationDuringIssuanceSupport.isPresentationGatedCredentialRequestedInSession(authSession)) {
            String sameDeviceLink = buildSameDeviceRequestLink(authSession);
            if (StringUtil.isNotBlank(sameDeviceLink)) {
                logger.debugf("Replacing username/password login with a same-device OpenID4VP presentation "
                        + "for a presentation-gated issuance request");
                logger.debugf("Same device request link is %s", sameDeviceLink);
                return Response.seeOther(URI.create(sameDeviceLink)).build();
            }
            logger.warnf("Presentation-gated issuance request resolved no usable same-device OpenID4VP "
                    + "presentation; falling back to the regular login flow");
        }
        return super.handleBrowserAuthenticationRequest(authSession, protocol, isPassive, redirectToAuthentication);
    }

    /**
     * Generates a same-device {@code openid4vp://} authorization request link for the enforced
     * presentation profile of the gated credential requested in this session.
     *
     * <p>The presentation replaces authentication. When the intercepted OIDC request carries an
     * {@code issuer_state} for a credential offer, the offer's target user is bound for a
     * session-identity profile; otherwise the OpenID4VP authenticator recovers the user from the
     * presented credential (a credential-identity profile). The OIDC auth session being intercepted
     * is kept; its {@code login_action_url}
     * points to {@link OID4VPLoginActionsService}, which resumes the OIDC flow after presentation.
     *
     * @return the same-device request link, or {@code null} if it could not be produced
     */
    private String buildSameDeviceRequestLink(AuthenticationSessionModel authSession) {
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
                    buildLoginActionUrl(authSession),
                    true);
            // An OID4VCI authorization-code request may already identify the issuance subject through
            // issuer_state. Bind that known subject for session-identity profiles, while retaining
            // credential-identity recovery for ordinary nested presentation requests.
            String subjectUserId = resolveOfferSubjectUserId(authSession);
            AuthorizationContext authContext = oid4vp.startAuthentication(
                    authSession.getClient().getClientId(),
                    profileId,
                    oidcAuthSession,
                    null,
                    subjectUserId);
            return authContext.getAuthorizationRequest();
        } catch (RuntimeException e) {
            logger.warnf(e, "Failed to build a same-device OpenID4VP presentation for presentation during issuance");
            return null;
        }
    }

    /**
     * Resolves the target user from the server-side credential offer carried by the OIDC request.
     * The issuer state is read from the note populated by {@link AuthorizationEndpoint}; it is
     * never trusted as a user identifier itself.
     */
    private String resolveOfferSubjectUserId(AuthenticationSessionModel authSession) {
        String issuerState = authSession.getClientNote(
                AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX
                        + OAuth2Constants.ISSUER_STATE);
        if (StringUtil.isBlank(issuerState)) {
            return null;
        }

        try {
            String offerId = IssuerState.fromEncodedString(issuerState).getCredentialsOfferId();
            if (StringUtil.isBlank(offerId)) {
                return null;
            }
            CredentialOfferState offerState = session.getProvider(CredentialOfferStorage.class)
                    .getOfferStateById(offerId);
            return offerState == null ? null : offerState.getTargetUserId();
        } catch (RuntimeException e) {
            logger.debugf(e, "Could not resolve nested-flow credential offer subject");
            return null;
        }
    }

    /**
     * Builds the {@link OID4VPLoginActionsService} login-action URL used to resume the OIDC flow
     * after a successful same-device presentation on this authentication session.
     */
    private String buildLoginActionUrl(AuthenticationSessionModel authSession) {
        String authSessionId = new AuthenticationSessionManager(session)
                .signAndEncodeToBase64AuthSessionId(authSession.getParentSession().getId());
        String sessionCode = new ClientSessionCode(session, realm, authSession).getOrGenerateCode();
        String execution = resolveFirstBrowserFlowExecution(authSession);

        return UriBuilder.fromUri(session.getContext().getUri().getBaseUri())
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPLoginActionsServiceFactory.PROVIDER_ID)
                .path(OID4VPLoginActionsService.OID4VP_AUTH_LOGIN_PATH)
                .queryParam(LoginActionsService.AUTH_SESSION_ID, authSessionId)
                .queryParam(LoginActionsService.SESSION_CODE, sessionCode)
                .queryParam(Constants.EXECUTION, execution)
                .queryParam(Constants.CLIENT_ID, authSession.getClient().getClientId())
                .queryParam(Constants.TAB_ID, authSession.getTabId())
                .build(realm.getName())
                .toString();
    }

    private String resolveFirstBrowserFlowExecution(AuthenticationSessionModel authSession) {
        AuthenticationFlowModel flow = AuthenticationFlowResolver.resolveBrowserFlow(authSession);
        return flow == null
                ? null
                : realm.getAuthenticationExecutionsStream(flow.getId()).findFirst().map(exec -> exec.getId()).orElse(null);
    }
}
