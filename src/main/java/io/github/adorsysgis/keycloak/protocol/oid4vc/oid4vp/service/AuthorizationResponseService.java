package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationResult;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationService;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.MediaType;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    public static final String PARENT_AUTH_SESSION_ID = "parent_auth_session_id";

    private final KeycloakSession session;
    private final VpTokenValidationService vpTokenValidationService;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
        this.vpTokenValidationService = new VpTokenValidationService(session);
    }

    /**
     * Processes authorization response for user authentication.
     */
    public void processAuthorizationResponse(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionModel authSession,
            AuthenticationProcessor authProcessor) {
        logger.debug("Processing authorization response for user authentication...");
        AuthenticationSessionStore store = new AuthenticationSessionStore(authSession);

        // Validate that authorization context is not yet closed
        if (authContext.getStatus().equals(AuthorizationContextStatus.SUCCESS)) {
            throw failWithHttpException(
                    ProcessingError.AUTH_CONTEXT_CLOSED,
                    "Authorization context is already closed. Cannot process further responses",
                    "Authorization context is already closed. Cannot process further responses",
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }

        VpTokenValidationResult validationResult;
        try {
            logger.debug("Running verifier-side vp_token validation pipeline");
            validationResult = vpTokenValidationService.validate(
                    responseObject, authContext.getRequestObject());
        } catch (VpTokenValidationException e) {
            logger.errorf(e, "vp_token validation failed");
            boolean formatFailure = VpTokenValidationException.Phase.FORMAT.equals(e.getPhase());
            String detailedMessage = formatFailure
                    ? String.format("Invalid SD-JWT presentation (%s)", e.getMessage())
                    : e.getMessage();
            throw failWithHttpException(
                    formatFailure ? ProcessingError.VP_TOKEN_AUTH_ERROR : ProcessingError.INVALID_VP_TOKEN,
                    formatFailure ? "Invalid SD-JWT presentation" : "Invalid vp_token",
                    detailedMessage,
                    formatFailure ? Response.Status.UNAUTHORIZED : Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }

        String sdJwtVp = validationResult.requireSinglePresentation().encodedPresentation();

        logger.debugf("Initializing authentication with validated SD-JWT VP token");
        var processorSession = authProcessor.getAuthenticationSession();
        processorSession.setAuthNote(SdJwtAuthenticator.SDJWT_TOKEN_KEY, sdJwtVp);
        processorSession.setAuthNote(SdJwtAuthenticator.VP_TOKEN_VALIDATED_KEY, "true");

        // Run authentication processor to resolve the presenting user
        logger.debug("Running authentication processor after vp_token validation...");
        try (Response response = authProcessor.authenticateOnly()) {
            if (response != null) {
                String detailed = getAuthenticatorErrorMessage(response);
                logger.errorf("Authentication processor failed. [%s] %s", response.getStatus(), detailed);

                throw failWithHttpException(
                        ProcessingError.VP_TOKEN_AUTH_ERROR,
                        "Invalid SD-JWT presentation",
                        detailed,
                        Response.Status.fromStatusCode(response.getStatus()),
                        authContext,
                        store);
            }
        }

        // Log authentication success and retrieve authenticated session
        logger.debug("Authentication processor succeeded, retrieving user session...");
        AuthenticatedClientSessionModel clientSession =
                authProcessor.attachSession().getClientSession();
        logger.infof("Client session id: %s", clientSession.getId());

        // Produce an authorization code for the authenticated user
        String authorizationCode = produceAuthorizationCode(clientSession, authContext);
        authContext.setStatus(AuthorizationContextStatus.SUCCESS);
        authContext.setAuthorizationCode(authorizationCode);

        // Persist authorization context
        store.storeAuthorizationContext(authContext);
    }

    private static String getAuthenticatorErrorMessage(Response response) {
        Object responseEntity = response.getEntity();
        if (!(responseEntity instanceof OAuth2ErrorRepresentation errorResponse)) {
            throw new IllegalStateException(String.format(
                    "Unexpected error response type from authenticator: %s",
                    responseEntity.getClass().getName()));
        }

        return String.format("%s: %s", errorResponse.getError().toUpperCase(), errorResponse.getErrorDescription());
    }

    /**
     * Issues an authorization code provided successful authentication.
     */
    private String produceAuthorizationCode(
            AuthenticatedClientSessionModel clientSession, AuthorizationContext authContext) {
        // Decorate client session with contextual notes

        if (authContext.getParentAuthSessionId() != null) {
            clientSession.setNote(PARENT_AUTH_SESSION_ID, authContext.getParentAuthSessionId());
        }

        clientSession.setNote(
                OIDCLoginProtocol.ISSUER,
                Urls.realmIssuer(
                        session.getContext().getUri().getBaseUri(),
                        session.getContext().getRealm().getName()));

        clientSession.setNote(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP);

        // Gather code data and generate authorization code

        String code = UUID.randomUUID().toString();
        String nonce = SecretGenerator.getInstance().randomString();
        int expiration = Time.currentTime() + clientSession.getRealm().getAccessCodeLifespan();

        OAuth2Code codeData = new OAuth2Code(
                code,
                expiration,
                nonce,
                OAuth2Constants.SCOPE_OPENID,
                clientSession.getUserSession().getId());

        return OAuth2CodeParser.persistCode(session, clientSession, codeData);
    }

    /**
     * Helper method for issuing exceptions while keeping a record in the authorization context.
     */
    private WebApplicationException failWithHttpException(
            ProcessingError error,
            String genericMessage,
            String detailedMessage,
            Response.Status status,
            AuthorizationContext authorizationContext,
            AuthenticationSessionStore store) {
        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(store.authenticationSession());
        String message = ProcessingError.AUTH_CONTEXT_CLOSED.equals(error)
                ? genericMessage
                : ErrorResponseSanitizer.withCorrelationId(correlationId)
                        .clientDescription(genericMessage, detailedMessage);

        logger.errorf("[%s] %s: %s", correlationId, error, detailedMessage);

        var errorResponse = new OAuth2ErrorRepresentation(error.getErrorString(), message);
        var httpErrorResponse = Response.status(status).entity(errorResponse).type(MediaType.APPLICATION_JSON);

        WebApplicationException exception = new WebApplicationException(
                CorsService.forWebOrigins(store.authenticationSession()).add(httpErrorResponse));

        // Update the authorization context with error details
        if (!error.equals(ProcessingError.AUTH_CONTEXT_CLOSED)) {
            authorizationContext
                    .setStatus(AuthorizationContextStatus.ERROR)
                    .setError(error)
                    .setErrorDescription(message);
            store.storeAuthorizationContext(authorizationContext);
        }

        return exception;
    }
}
