package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.ClientSessionCode.ActionType;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resources.LoginActionsService;
import org.keycloak.services.resources.SessionCodeChecks;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel.Action;

/**
 * Adds form action endpoint for completing OpenID4VP authentication after QR code scanning.
 */
public class OID4VPLoginActionsService extends LoginActionsService implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(OID4VPLoginActionsService.class);

    public static final String OID4VP_AUTH_LOGIN_PATH = "oid4vp-auth-login";

    private final EventBuilder event;
    private final RealmModel realm;
    private final HttpRequest request;
    private final ClientConnection clientConnection;

    public OID4VPLoginActionsService(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.event = event;
        this.realm = session.getContext().getRealm();
        this.request = session.getContext().getHttpRequest();
        this.clientConnection = session.getContext().getConnection();
    }

    // Mirrors LoginActionsService#checksForCode
    // Duplicated because private in superclass
    @SuppressWarnings("SameParameterValue")
    private SessionCodeChecks checksForCode(
            String authSessionId,
            String code,
            String execution,
            String clientId,
            String tabId,
            String clientData,
            String flowPath) {
        SessionCodeChecks res = new SessionCodeChecks(
                realm,
                session.getContext().getUri(),
                request,
                clientConnection,
                session,
                event,
                authSessionId,
                code,
                execution,
                clientId,
                tabId,
                clientData,
                flowPath);

        res.initialVerify();
        return res;
    }

    @Path(OID4VP_AUTH_LOGIN_PATH)
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response oid4vpAuthLogin(
            @QueryParam(AUTH_SESSION_ID) String authSessionId,
            @QueryParam(SESSION_CODE) String code,
            @QueryParam(Constants.EXECUTION) String execution,
            @QueryParam(Constants.CLIENT_ID) String clientId,
            @QueryParam(Constants.CLIENT_DATA) String clientData,
            @QueryParam(Constants.TAB_ID) String tabId,
            @FormParam(OAuth2Constants.CODE) String authorizationCode) {
        SessionCodeChecks checks =
                checksForCode(authSessionId, code, execution, clientId, tabId, clientData, AUTHENTICATE_PATH);

        if (!checks.verifyActiveAndValidAction(Action.AUTHENTICATE.name(), ActionType.LOGIN)) {
            return checks.getResponse();
        }

        // Recover URI context and OIDC auth session
        KeycloakUriInfo uriInfo = session.getContext().getUri();
        AuthenticationSessionModel authSession = checks.getAuthenticationSession();

        // Validate authorization code
        logger.debugf("Validating authorization code: %s", authorizationCode);
        OAuth2CodeParser.ParseResult result = OAuth2CodeParser.parseCode(session, authorizationCode, realm, event);
        if (result.isIllegalCode() || result.isExpiredCode()) {
            String errorMessage = "Authorization code not valid";
            event.error(Errors.INVALID_CODE);
            return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, errorMessage);
        }

        // Attach authenticated user to OIDC sessions
        authSession.setAuthenticatedUser(
                result.getClientSession().getUserSession().getUser());
        ClientSessionContext clientSessionCtx =
                AuthenticationProcessor.attachSession(authSession, null, session, realm, clientConnection, event);
        UserSessionModel freshUserSession = clientSessionCtx.getClientSession().getUserSession();

        // Append note conveying this login method
        freshUserSession.setNote(PARAM_LOGIN_METHOD, OID4VP_AUTH_LOGIN_PATH);

        logger.debugf("Attempting redirection after successful OID4VP authentication");
        return AuthenticationManager.redirectAfterSuccessfulFlow(
                session,
                realm,
                freshUserSession,
                clientSessionCtx,
                request,
                uriInfo,
                clientConnection,
                event,
                authSession);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}
}
