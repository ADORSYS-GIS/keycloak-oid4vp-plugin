package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapabilities;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.VerificationException;
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
    private final DcqlCredentialCapabilities dcqlCapabilities;

    public AuthorizationResponseService(KeycloakSession session) {
        this(session, DcqlCredentialCapabilities.createDefault());
    }

    public AuthorizationResponseService(KeycloakSession session, DcqlCredentialCapabilities dcqlCapabilities) {
        this.session = session;
        this.dcqlCapabilities = dcqlCapabilities;
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

        // Extract SD-JWT VP token from the response object
        String sdJwtVp = extractSdJwtVpToken(responseObject, authContext, store);

        logger.debugf("Initializing authentication with extracted SD-JWT VP token");
        var processorSession = authProcessor.getAuthenticationSession();
        var dcqlQuery = authContext.getRequestObject().getDcqlQuery();
        var dcqlCapability = dcqlCapabilities.resolveForPresentation(dcqlQuery);
        dcqlCapability.setupAuthenticationSession(processorSession, sdJwtVp, authContext);

        // Run authentication processor to validate the SD-JWT VP token
        logger.debug("Running authentication processor to validate SD-JWT VP token...");
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
     * Extract SD-JWT VP token from response object
     */
    private String extractSdJwtVpToken(
            ResponseObject responseObject, AuthorizationContext authContext, AuthenticationSessionStore store) {
        String parsedVpToken;
        logger.debug("Extracting VP token from response object with DCQL matching");
        parsedVpToken = extractVpTokenWithDCQL(responseObject, authContext, store);

        try {
            String vpToken = decodeIfBase64Url(parsedVpToken);
            var dcqlQuery = authContext.getRequestObject().getDcqlQuery();
            dcqlCapabilities.resolveForPresentation(dcqlQuery).validatePresentation(dcqlQuery, vpToken);
            return vpToken;
        } catch (VerificationException e) {
            logger.errorf(e, "Presented credential does not satisfy DCQL query");
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid vp_token",
                    e.getMessage(),
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Failed to parse SD-JWT VP token");
            String detailed = "Could not parse SD-JWT VP token contained in `vp_token`";
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid vp_token",
                    detailed,
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }
    }

    /**
     * Extract VP token from response object (DCQL era)
     */
    private String extractVpTokenWithDCQL(
            ResponseObject responseObject, AuthorizationContext authContext, AuthenticationSessionStore store) {
        var dcqlQuery = authContext.getRequestObject().getDcqlQuery();
        if (dcqlQuery == null || dcqlQuery.getCredentials().size() != 1) {
            throw new IllegalStateException(
                    "Invalid DCQL query in authorization context. Expected exactly one credential query.");
        }

        // Ensure that VP token map matches the DCQL credential query
        var credentialQuery = dcqlQuery.getCredentials().getFirst();
        var vpTokenMap = responseObject.getVpToken();
        if (vpTokenMap == null || !vpTokenMap.containsKey(credentialQuery.getId())) {
            String detailed = "Presented vp_token map does not match DCQL credential query";
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid vp_token",
                    detailed,
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }

        // Check that the VP token map provides a VP token, and only one
        var tokens = vpTokenMap.get(credentialQuery.getId());
        if (tokens == null || tokens.size() != 1) {
            String errorMsg = String.format(
                    "Presented vp_token map must contain exactly one token as requested. Found: %d",
                    tokens == null ? 0 : tokens.size());

            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid vp_token",
                    errorMsg,
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }

        return (String) tokens.getFirst();
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

    /**
     * Helper method to decode Base64URL encoded strings if applicable.
     * If the input is not Base64URL encoded, it returns the input as is.
     */
    private static String decodeIfBase64Url(String input) {
        try {
            // Try to decode as Base64URL
            byte[] decoded = Base64.getUrlDecoder().decode(input);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Not valid Base64URL, return as is
            return input;
        }
    }
}
