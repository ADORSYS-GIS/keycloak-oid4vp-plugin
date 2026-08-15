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
import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.AuthenticationFlowResolver;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/** Replaces the browser login with same-device OpenID4VP for nested issuance requests. */
public class ExtendedOIDCAuthorizationEndpoint extends AuthorizationEndpoint {

    private static final Logger logger = Logger.getLogger(ExtendedOIDCAuthorizationEndpoint.class);

    private final KeycloakSession session;
    private final EventBuilder event;
    private final RealmModel realm;

    private final PresentationDuringIssuanceService presentationService;

    public ExtendedOIDCAuthorizationEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.session = session;
        this.event = event;
        this.realm = session.getContext().getRealm();
        this.presentationService = new PresentationDuringIssuanceService(session);
    }

    @Override
    protected Response handleBrowserAuthenticationRequest(
            AuthenticationSessionModel authSession,
            LoginProtocol protocol,
            boolean isPassive,
            boolean redirectToAuthentication) {
        // Passive (prompt=none) requests should not trigger an interactive presentation.
        if (!isPassive && presentationService.isPresentationGatedCredentialRequestedInSession(authSession)) {
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

    /** Returns a same-device request for the profile enforced by the credential configuration. */
    private String buildSameDeviceRequestLink(AuthenticationSessionModel authSession) {
        String profileId = presentationService.resolveEnforcedProfileId(authSession);
        if (StringUtil.isBlank(profileId)) {
            logger.warnf("Presentation-gated issuance request resolved no enforced OpenID4VP profile; "
                    + "cannot build a same-device presentation");
            return null;
        }

        try {
            session.getContext().setAuthenticationSession(authSession);
            OID4VPUserAuthEndpoint oid4vp = new OID4VPUserAuthEndpoint(session, event);
            String authSessionId = OID4VPUserAuthEndpointBase.getAuthSessionId(authSession);
            OIDCAuthSession oidcAuthSession =
                    new OIDCAuthSession(authSessionId, buildLoginActionUrl(authSession), true);
            String subjectUserId = presentationService.resolveOfferSubjectUserId(authSession);
            AuthorizationContext authContext = oid4vp.startAuthentication(
                    authSession.getClient().getClientId(), profileId, oidcAuthSession, null, subjectUserId);
            return authContext.getAuthorizationRequest();
        } catch (RuntimeException e) {
            logger.warnf(e, "Failed to build a same-device OpenID4VP presentation for presentation during issuance");
            return null;
        }
    }

    /**
     * Builds the {@link OID4VPLoginActionsService} login-action URL used to resume the OIDC flow
     * after a successful same-device presentation on this authentication session.
     */
    private String buildLoginActionUrl(AuthenticationSessionModel authSession) {
        String authSessionId = new AuthenticationSessionManager(session)
                .signAndEncodeToBase64AuthSessionId(
                        authSession.getParentSession().getId());
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
                : realm.getAuthenticationExecutionsStream(flow.getId())
                        .findFirst()
                        .map(exec -> exec.getId())
                        .orElse(null);
    }
}
