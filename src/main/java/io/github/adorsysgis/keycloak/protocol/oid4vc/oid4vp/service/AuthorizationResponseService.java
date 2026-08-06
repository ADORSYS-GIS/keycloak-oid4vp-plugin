package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapabilities;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapability;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlResponseCredentialSelector;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
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
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    public static final String PARENT_AUTH_SESSION_ID = "parent_auth_session_id";

    private final KeycloakSession session;
    private final DcqlCredentialCapabilities dcqlCapabilities;

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
            AuthenticationProcessor authProcessor,
            AuthenticationProfile profile) {
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

        // Propagate authorization context to processor session
        AuthenticationSessionModel authProcessorSession = authProcessor.getAuthenticationSession();
        new AuthenticationSessionStore(authProcessorSession).storeAuthorizationContext(authContext);

        // Collect and pass presented tokens as session note so the authenticator can pick them up
        HashMap<String, String> presentedTokens = extractPresentedTokens(responseObject, profile, store, authContext);
        authProcessorSession.setAuthNote(
                OID4VPAuthenticator.PRESENTED_TOKENS_KEY, JsonSerialization.valueAsString(presentedTokens));

        // Run authentication processor to validate the presented credentials
        logger.debug("Running authentication processor to validate presented credentials...");
        try (Response response = authProcessor.authenticateOnly()) {
            if (response != null) {
                String detailed = getAuthenticatorErrorMessage(response);
                logger.errorf("Authentication processor failed. [%s] %s", response.getStatus(), detailed);

                throw failWithHttpException(
                        ProcessingError.VP_TOKEN_AUTH_ERROR,
                        "Invalid credential presentation",
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

    // ---- Token extraction ----------------------------------------------------

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
     * Extracts exactly one decoded credential token per selected DCQL credential ID.
     *
     * <p>The response object keeps the wire-level vp_token shape, where each DCQL
     * credential ID maps to a list. The authenticator needs a normalized lookup map
     * so it can verify the selected primary credential and supporting credentials
     * inside the same Keycloak authentication execution before marking the flow successful.
     */
    private HashMap<String, String> extractPresentedTokens(
            ResponseObject responseObject,
            AuthenticationProfile profile,
            AuthenticationSessionStore store,
            AuthorizationContext authContext) {
        var vpTokenMap = responseObject.getVpToken();
        HashMap<String, String> tokens = new HashMap<>();

        if (vpTokenMap == null) {
            throw failInvalidVpToken("Presented vp_token map is missing", authContext, store);
        }

        Map<String, CredentialRequirement> credentialsById = profile.getCredentials().stream()
                .collect(Collectors.toMap(CredentialRequirement::getId, credential -> credential));
        Set<String> selectedCredentialIds;
        try {
            selectedCredentialIds = DcqlResponseCredentialSelector.selectPresentedCredentialIds(
                    authContext.getRequestObject().getDcqlQuery(), vpTokenMap.keySet());
        } catch (IllegalArgumentException e) {
            throw failInvalidVpToken(e.getMessage(), authContext, store);
        }

        for (String credentialId : vpTokenMap.keySet()) {
            if (!credentialsById.containsKey(credentialId)) {
                throw failInvalidVpToken(
                        "Presented vp_token map contains unknown credential: " + credentialId, authContext, store);
            }
            if (!selectedCredentialIds.contains(credentialId)) {
                throw failInvalidVpToken(
                        "Presented vp_token map contains credential outside the selected group options: "
                                + credentialId,
                        authContext,
                        store);
            }
        }

        for (String credentialId : selectedCredentialIds) {
            CredentialRequirement credential = credentialsById.get(credentialId);
            var credentialTokens = vpTokenMap.get(credentialId);
            if (credentialTokens == null || credentialTokens.size() != 1) {
                String errorMsg = String.format(
                        "Presented vp_token map must contain exactly one token for credential '%s'. Found: %d",
                        credentialId, credentialTokens == null ? 0 : credentialTokens.size());
                throw failInvalidVpToken(errorMsg, authContext, store);
            }

            String rawToken = credentialTokens.getFirst();
            // mDoc tokens are base64url-encoded CBOR — decoding as UTF-8 would corrupt
            // the binary data, so keep the wire form for mDoc.
            CredentialFormat format = CredentialFormat.fromValue(credential.getFormat());
            String presentedToken =
                    switch (format) {
                        case SD_JWT_VC -> decodeIfBase64Url(rawToken);
                        case MSO_MDOC -> rawToken;
                    };

            validatePresentedToken(presentedToken, credentialId, authContext, store);
            tokens.put(credentialId, presentedToken);
        }

        return tokens;
    }

    /**
     * Pre-validates a single presented token against its DCQL credential query.
     */
    private void validatePresentedToken(
            String presentedToken,
            String credentialId,
            AuthorizationContext authContext,
            AuthenticationSessionStore store) {
        DcqlQuery dcqlQuery = authContext.getRequestObject().getDcqlQuery();
        Credential credentialQuery = dcqlQuery.getCredentials().stream()
                .filter(candidate -> credentialId.equals(candidate.getId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("DCQL query has no credential id: " + credentialId));

        DcqlCredentialCapability capability = dcqlCapabilities.resolve(credentialQuery.getFormat());
        if (!capability.supportsPresentationPreValidation()) {
            logger.debugf(
                    "Skipping DCQL pre-validation for credential '%s' (format: %s); "
                            + "the capability delegates full verification to the authenticator",
                    credentialId, credentialQuery.getFormat());
            return;
        }

        try {
            capability.validatePresentation(credentialQuery, presentedToken);
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
            logger.errorf(e, "Failed to parse presented credential token");
            throw failInvalidVpToken("Could not parse credential token contained in `vp_token`", authContext, store);
        }
    }

    private WebApplicationException failInvalidVpToken(
            String detailed, AuthorizationContext authContext, AuthenticationSessionStore store) {
        throw failWithHttpException(
                ProcessingError.INVALID_VP_TOKEN,
                "Invalid vp_token",
                detailed,
                Response.Status.BAD_REQUEST,
                authContext,
                store);
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

        // Mark the user session as presentation-verified so the issuance gate can enforce that the
        // authorization code was obtained via a Verifiable Presentation (OID4VCI Interactive
        // Authorization). This marker is the carrier consumed at the credential endpoint.
        clientSession.getUserSession().setNote(OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE, Boolean.TRUE.toString());

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
