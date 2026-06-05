package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.PresentedCredential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenDcqlValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.VpTokenValidationException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.util.List;
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
import org.keycloak.util.JsonSerialization;
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
    private final VpTokenDcqlValidator vpTokenDcqlValidator;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
        this.vpTokenDcqlValidator = new VpTokenDcqlValidator();
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

        // Validate DCQL satisfaction, then extract the SD-JWT VP for authentication.
        String sdJwtVp = validateDcqlAndExtractSdJwtVpToken(responseObject, authContext, store);

        logger.debugf("Initializing authentication with DCQL-validated SD-JWT VP token");
        var processorSession = authProcessor.getAuthenticationSession();
        String nonce = authContext.getRequestObject().getNonce();
        String aud = authContext.getRequestObject().getClientId();
        processorSession.setAuthNote(SdJwtAuthenticator.SDJWT_TOKEN_KEY, sdJwtVp);
        processorSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_NONCE_KEY, nonce);
        processorSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_AUD_KEY, aud);

        boolean requireCryptographicHolderBinding = isCryptographicHolderBindingRequired(
                authContext.getRequestObject().getDcqlQuery().getCredentials());
        processorSession.setAuthNote(
                SdJwtAuthenticator.REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY,
                String.valueOf(requireCryptographicHolderBinding));

        var transactionData = authContext.getRequestObject().getTransactionData();
        if (transactionData != null && !transactionData.isEmpty()) {
            try {
                processorSession.setAuthNote(
                        SdJwtAuthenticator.TRANSACTION_DATA_WIRE_KEY,
                        JsonSerialization.writeValueAsString(transactionData));
            } catch (Exception e) {
                throw new IllegalStateException("Failed to persist transaction_data for validation", e);
            }
        }

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

    private static boolean isCryptographicHolderBindingRequired(List<Credential> credentials) {
        return credentials.stream().noneMatch(c -> Boolean.FALSE.equals(c.getRequireCryptographicHolderBinding()));
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
     * Validates returned presentations against the issued DCQL query and extracts the single SD-JWT VP
     * used by the login flow.
     */
    private String validateDcqlAndExtractSdJwtVpToken(
            ResponseObject responseObject, AuthorizationContext authContext, AuthenticationSessionStore store) {
        var dcqlQuery = authContext.getRequestObject().getDcqlQuery();
        if (dcqlQuery == null || dcqlQuery.getCredentials().size() != 1) {
            throw new IllegalStateException(
                    "Invalid DCQL query in authorization context. Expected exactly one credential query.");
        }

        try {
            List<PresentedCredential> validated = vpTokenDcqlValidator.validate(responseObject.getVpToken(), dcqlQuery);
            if (validated.size() != 1) {
                throw new VpTokenValidationException(
                        VpTokenValidationException.Phase.STRUCTURE,
                        "Presented vp_token map must contain exactly one token as requested. Found: "
                                + validated.size());
            }
            return validated.getFirst().encodedPresentation();
        } catch (VpTokenValidationException e) {
            logger.errorf(e, "vp_token DCQL validation failed");
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid vp_token",
                    e.getMessage(),
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }
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
