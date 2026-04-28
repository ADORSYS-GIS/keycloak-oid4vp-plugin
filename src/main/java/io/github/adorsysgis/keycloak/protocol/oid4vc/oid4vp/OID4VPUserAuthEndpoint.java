package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import com.apicatalog.jsonld.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Endpoint class for user authentication over
 * <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html">
 * OpenID4VP
 * </a>.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpoint extends OID4VPUserAuthEndpointBase implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpoint.class);

    public static final String REQUEST_JWT_PATH = "/request.jwt";
    public static final String RESPONSE_URI_PATH = "/response";
    public static final String AUTH_STATUS_PATH = "/status/{transactionId}";
    public static final String AUTH_CODE_PATH = "/code";

    private final AuthorizationRequestService authorizationRequestService;
    private final AuthorizationResponseService authorizationResponseService;

    public OID4VPUserAuthEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.authorizationRequestService = new AuthorizationRequestService(session);
        this.authorizationResponseService = new AuthorizationResponseService(session);
    }

    @OPTIONS
    @Path("{any:.*}")
    public Response preflight() {
        return CorsService.openPreflight().add(Response.ok());
    }

    /**
     * Generates an OpenID4VP authentication request for user authentication.
     */
    @GET
    @Path("/request")
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthenticationRequest(
            @QueryParam(OAuth2Constants.CLIENT_ID) String clientId,
            @QueryParam(OAuth2Constants.CODE_CHALLENGE) String codeChallenge,
            @QueryParam(OAuth2Constants.CODE_CHALLENGE_METHOD) String codeChallengeMethod) {
        logger.debug("Initiating user authentication over OpenID4VP...");

        try {
            checkClient(clientId);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(
                    errorResponse(
                            Response.Status.BAD_REQUEST,
                            OAuthErrorException.INVALID_CLIENT,
                            "Cannot proceed with provided client ID"),
                    e);
        }

        AuthorizationContext authContext;
        try {
            authContext = startAuthentication(clientId, null, codeChallenge, codeChallengeMethod);
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(
                    errorResponse(Response.Status.BAD_REQUEST, OAuthErrorException.INVALID_REQUEST, e.getMessage()), e);
        }

        AuthenticationSessionModel authSession = recoverAuthenticationSession(authContext.getTransactionId());

        return CorsService.forWebOrigins(authSession).add(Response.ok(authContext));
    }

    /**
     * Dereferences request URIs into signed request objects.
     */
    @GET
    @Path(REQUEST_JWT_PATH + "/{requestId}")
    @Produces(MediaType.TEXT_PLAIN)
    public Response getSignedRequestObject(@PathParam("requestId") String requestId) {
        logger.debug("Resolving request URI to signed request object...");
        AuthorizationContext authorizationContext = recoverAuthorizationContextByRequestId(requestId);
        String requestObjectJwt = authorizationContext.getRequestObjectJwt();
        return CorsService.open().add(Response.ok(requestObjectJwt));
    }

    /**
     * Processes authentication responses from the wallet toward user authentication.
     */
    @POST
    @Path(RESPONSE_URI_PATH + "/{requestId}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response processAuthorizationResponse(
            @PathParam("requestId") String requestId,
            @FormParam("response") String encryptedResponse,
            @FormParam(ResponseObject.VP_TOKEN_KEY) String vpToken,
            @FormParam(ResponseObject.PRESENTATION_SUBMISSION_KEY) String presentationSubmission,
            @FormParam(ResponseObject.STATE_KEY) String state) {
        logger.debug("Processing authorization response for user authentication...");

        // Recover the auth session and context given the request ID param
        AuthorizationContext authorizationContext = recoverAuthorizationContextByRequestId(requestId);
        AuthenticationSessionModel authSession = recoverAuthenticationSession(requestId);

        // Validate that response is encrypted if required
        String ephemeralKey = authorizationContext.getEphemeralKey();
        boolean expectsEncrypted = StringUtils.isNotBlank(ephemeralKey);
        boolean hasEncrypted = StringUtils.isNotBlank(encryptedResponse);
        if (expectsEncrypted != hasEncrypted) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    String.format(
                            "Authorization context expects %s response",
                            StringUtils.isBlank(encryptedResponse) ? "encrypted" : "unencrypted")));
        }

        // Parse a response object from the request parameters
        ResponseObject responseObject;
        try {
            responseObject = StringUtils.isBlank(encryptedResponse)
                    ? new ResponseObject(vpToken, presentationSubmission, state)
                    : decryptResponse(encryptedResponse, ephemeralKey);

            String parsedState = responseObject.getState();
            if (StringUtils.isNotBlank(parsedState) && !requestId.equals(parsedState)) {
                throw new IllegalArgumentException(String.format(
                        "State param must match requestId. requestId: %s, state: %s",
                        requestId, responseObject.getState()));
            }
        } catch (IllegalArgumentException | JsonProcessingException e) {
            throw new BadRequestException(
                    errorResponse(
                            Response.Status.BAD_REQUEST,
                            OAuthErrorException.INVALID_REQUEST,
                            String.format("Unparseable response params (%s)", e.getMessage())),
                    e);
        }

        // Call delegate service to process the authorization response
        AuthenticationProcessor authProcessor = getAuthenticationProcessor();
        authorizationResponseService.processAuthorizationResponse(
                responseObject, authorizationContext, authSession, authProcessor);

        // Successful. Return empty object
        return CorsService.open().add(Response.ok(Map.of()));
    }

    /**
     * Inquire the state of an authorization request context by its transaction ID.
     * In cross-device flows, the wallet should poll this endpoint.
     */
    @GET
    @Path(AUTH_STATUS_PATH)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getAuthorizationContextState(@PathParam("transactionId") String transactionId) {
        logger.debug("Inquiring authorization context state by transaction ID...");
        AuthenticationSessionModel authSession;
        AuthorizationContext authorizationContext;

        try {
            authSession = this.recoverAuthenticationSession(transactionId);
            authorizationContext =
                    new AuthenticationSessionStore(authSession).getAuthorizationContextByTransactionId(transactionId);
        } catch (IllegalArgumentException e) {
            throw new NotFoundException(
                    errorResponse(
                            Response.Status.NOT_FOUND,
                            OAuthErrorException.INVALID_REQUEST,
                            "Authorization context not found for transaction ID: " + transactionId),
                    e);
        }

        AuthorizationContext reducedContext = new AuthorizationContext()
                .setStatus(authorizationContext.getStatus())
                .setError(authorizationContext.getError())
                .setErrorDescription(authorizationContext.getErrorDescription());

        if (!StringUtil.isBlank(authorizationContext.getParentAuthSessionId())) {
            reducedContext.setAuthorizationCode(authorizationContext.getAuthorizationCode());
        }

        return CorsService.forWebOrigins(authSession).add(Response.ok(reducedContext));
    }

    /**
     * Redeems an authorization code from a completed API authentication flow.
     */
    @POST
    @Path(AUTH_CODE_PATH)
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response redeemAuthorizationCode(
            @FormParam("transaction_id") String transactionId,
            @FormParam(OAuth2Constants.CODE_VERIFIER) String codeVerifier) {
        logger.debug("Redeeming authorization code for completed authentication...");

        AuthenticationSessionModel authSession;
        AuthorizationContext authorizationContext;
        try {
            authSession = this.recoverAuthenticationSession(transactionId);
            authorizationContext =
                    new AuthenticationSessionStore(authSession).getAuthorizationContextByTransactionId(transactionId);
        } catch (IllegalArgumentException e) {
            throw new NotFoundException(
                    errorResponse(
                            Response.Status.NOT_FOUND,
                            OAuthErrorException.INVALID_REQUEST,
                            "Authorization context not found for transaction ID: " + transactionId),
                    e);
        }

        if (!AuthorizationContextStatus.SUCCESS.equals(authorizationContext.getStatus())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    "Authorization has not completed successfully"));
        }

        if (!StringUtil.isBlank(authorizationContext.getParentAuthSessionId())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    "Authorization code must be completed through the bound OIDC session"));
        }

        if (StringUtil.isBlank(authorizationContext.getCodeChallenge())
                || StringUtil.isBlank(authorizationContext.getCodeChallengeMethod())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    "Authorization code redemption is not configured for this flow"));
        }

        if (StringUtil.isBlank(codeVerifier)
                || !PkceUtils.validateCodeChallenge(
                        codeVerifier,
                        authorizationContext.getCodeChallenge(),
                        authorizationContext.getCodeChallengeMethod())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_GRANT,
                    "Authorization code verifier not valid"));
        }

        AuthorizationContext responseContext =
                new AuthorizationContext().setAuthorizationCode(authorizationContext.getAuthorizationCode());
        return CorsService.forWebOrigins(authSession).add(Response.ok(responseContext));
    }

    /**
     * Initializes OpenID4VP authentication and return authorization context
     */
    public AuthorizationContext startAuthentication(String clientId, String parentAuthSessionId) {
        return startAuthentication(clientId, parentAuthSessionId, null, null);
    }

    /**
     * Initializes OpenID4VP authentication and return authorization context
     */
    public AuthorizationContext startAuthentication(
            String clientId, String parentAuthSessionId, String codeChallenge, String codeChallengeMethod) {
        logger.debug("Generating new authentication context...");

        String resolvedCodeChallengeMethod =
                validateOwnershipBinding(parentAuthSessionId, codeChallenge, codeChallengeMethod);

        ClientModel client = checkClient(clientId);
        AuthenticationSessionModel authSession = createAuthSession(client);
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);

        // Call delegate service to create an authorization request
        AuthorizationContext authorizationContext = authorizationRequestService.createAuthorizationRequest(
                authSession, parentAuthSessionId, config, codeChallenge, resolvedCodeChallengeMethod);

        return new AuthorizationContext()
                .setAuthorizationRequest(authorizationContext.getAuthorizationRequest())
                .setTransactionId(authorizationContext.getTransactionId());
    }

    /**
     * Loads client model associated with the given client ID
     */
    public ClientModel checkClient(String clientId) {
        ClientModel client = realm.getClientByClientId(clientId);

        if (client == null) {
            throw new IllegalArgumentException("Client is unknown");
        }

        if (!client.isEnabled()) {
            throw new IllegalArgumentException("Client is disabled");
        }

        return client;
    }

    /**
     * Recovers the authorization context linked to a request ID.
     */
    private AuthorizationContext recoverAuthorizationContextByRequestId(String requestId) throws NotFoundException {
        try {
            var authSession = this.recoverAuthenticationSession(requestId);
            return new AuthenticationSessionStore(authSession).getAuthorizationContextByRequestId(requestId);
        } catch (IllegalArgumentException e) {
            throw new NotFoundException(
                    errorResponse(
                            Response.Status.NOT_FOUND,
                            OAuthErrorException.INVALID_REQUEST,
                            "Authorization context not found for request ID: " + requestId),
                    e);
        }
    }

    /**
     * Recovers the authentication session linked to a possibly extended ID.
     */
    private AuthenticationSessionModel recoverAuthenticationSession(String extAuthSessionId) {
        String authSessionId = pruneAuthSessionId(extAuthSessionId);
        AuthenticationSessionModel authSession = getAuthSession(authSessionId)
                .orElseThrow(() -> new IllegalArgumentException(
                        "No authentication session attached to session ID: " + extAuthSessionId));

        session.getContext().setAuthenticationSession(authSession);
        return authSession;
    }

    /**
     * Decrypt response to authorization request.
     * @param encryptedResponse the assumed JWE encrypted response string
     * @param ephemeralKey the ephemeral key generated for the authentication session
     */
    private ResponseObject decryptResponse(String encryptedResponse, String ephemeralKey) {
        try {
            ECPrivateKey privKey = EphemeralKeyUtils.privateKeyFromBase64(ephemeralKey);
            String decryptedResponse = EphemeralKeyUtils.decrypt(encryptedResponse, privKey);
            return JsonSerialization.readValue(decryptedResponse, ResponseObject.class);
        } catch (JWEException | IOException e) {
            logger.error("Failed to decrypt response", e);
            throw new IllegalArgumentException("Failed to decrypt and parse response", e);
        }
    }

    /**
     * Prepares an invalid request response with the given status and error description.
     */
    private Response errorResponse(Response.Status status, String error, String errorDescription) {
        var errorResponse = new OAuth2ErrorRepresentation(error, errorDescription);
        return CorsService.open()
                .add(Response.status(status).entity(errorResponse).type(MediaType.APPLICATION_JSON));
    }

    private String validateOwnershipBinding(
            String parentAuthSessionId, String codeChallenge, String codeChallengeMethod) {
        boolean hasParentAuthSession = !StringUtil.isBlank(parentAuthSessionId);
        boolean hasCodeChallenge = !StringUtil.isBlank(codeChallenge);
        boolean hasCodeChallengeMethod = !StringUtil.isBlank(codeChallengeMethod);

        if (hasParentAuthSession) {
            if (hasCodeChallenge || hasCodeChallengeMethod) {
                throw new IllegalArgumentException(
                        "OIDC-bound OpenID4VP flows do not accept code challenge parameters");
            }
            return null;
        }

        if (!hasCodeChallenge && !hasCodeChallengeMethod) {
            throw new IllegalArgumentException(
                    "Public API requests must provide a code challenge for authorization code redemption");
        }

        if (!hasCodeChallenge || !hasCodeChallengeMethod) {
            throw new IllegalArgumentException("Both code_challenge and code_challenge_method are required");
        }

        if (!OAuth2Constants.PKCE_METHOD_S256.equals(codeChallengeMethod)) {
            throw new IllegalArgumentException("Only S256 code challenge method is supported");
        }

        return codeChallengeMethod;
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}
}
