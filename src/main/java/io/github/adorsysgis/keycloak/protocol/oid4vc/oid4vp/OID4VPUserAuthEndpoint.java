package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static org.keycloak.common.util.UriUtils.checkUrl;

import com.apicatalog.jsonld.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapabilities;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestUriMethod;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.CodeChallengeDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.InteractiveResponseConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ResponseStateValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation.AuthorizationResponseJweValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;
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
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Endpoint class for user authentication over
 * <a href=
 * "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">
 * OpenID4VP
 * </a>.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpoint extends OID4VPUserAuthEndpointBase implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthEndpoint.class);
    public static final String REQUEST_JWT_PATH = "/request.jwt";
    public static final String RESPONSE_URI_PATH = "/response";
    public static final String CALLBACK_URI_PATH = "/callback";
    public static final String AUTH_STATUS_PATH = "/status/{transactionId}";
    public static final String AUTH_CODE_PATH = "/code";
    public static final String AUTH_REQ_JWT_MEDIA_TYPE = "application/oauth-authz-req+jwt";
    public static final String PROFILE_ID_PARAM = "profile_id";

    private final AuthorizationRequestService authorizationRequestService;
    private final AuthorizationResponseService authorizationResponseService;

    public OID4VPUserAuthEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        var dcqlCapabilities = DcqlCredentialCapabilities.createDefault();
        this.authorizationRequestService = new AuthorizationRequestService(session, dcqlCapabilities);
        this.authorizationResponseService = new AuthorizationResponseService(session, dcqlCapabilities);
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
            @QueryParam(PROFILE_ID_PARAM) String profileId,
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
            authContext = startAuthentication(
                    clientId, profileId, null, new CodeChallengeDetails(codeChallenge, codeChallengeMethod));
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(
                    errorResponse(
                            Response.Status.BAD_REQUEST,
                            OAuthErrorException.INVALID_REQUEST,
                            "Invalid request parameters"),
                    e);
        }

        AuthenticationSessionModel authSession = recoverAuthenticationSession(authContext.getTransactionId());
        return CorsService.forWebOrigins(authSession).add(Response.ok(authContext));
    }

    /**
     * Dereferences request URIs into signed request objects.
     */
    @GET
    @Path(REQUEST_JWT_PATH + "/{requestId}")
    @Produces(AUTH_REQ_JWT_MEDIA_TYPE)
    public Response getSignedRequestObject(@PathParam("requestId") String requestId) {
        logger.debug("Resolving request URI to signed request object...");
        AuthorizationContext authorizationContext = recoverAuthorizationContextByRequestId(requestId);
        if (RequestUriMethod.POST.equals(authorizationContext.getRequestUriMethod())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST, "invalid_request_uri_method", "This request_uri requires HTTP POST"));
        }
        String requestObjectJwt = authorizationContext.getRequestObjectJwt();
        return CorsService.open().add(Response.ok(requestObjectJwt, AUTH_REQ_JWT_MEDIA_TYPE));
    }

    /**
     * Dereferences request URIs into signed request objects using
     * request_uri_method=post.
     */
    @POST
    @Path(REQUEST_JWT_PATH + "/{requestId}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(AUTH_REQ_JWT_MEDIA_TYPE)
    public Response postSignedRequestObject(
            @PathParam("requestId") String requestId,
            @FormParam("wallet_nonce") String walletNonce,
            @FormParam("wallet_metadata") String walletMetadata) {
        logger.debug("Resolving request URI to signed request object via POST...");
        validateRequestUriPostHeaders();
        validateRequestUriPostScheme();
        AuthorizationContext authorizationContext = recoverAuthorizationContextByRequestId(requestId);
        if (!RequestUriMethod.POST.equals(authorizationContext.getRequestUriMethod())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    "invalid_request_uri_method",
                    "This request_uri does not accept HTTP POST"));
        }

        JsonNode parsedWalletMetadata = null;
        if (StringUtil.isNotBlank(walletMetadata)) {
            try {
                parsedWalletMetadata = JsonSerialization.mapper.readTree(walletMetadata);
                if (!parsedWalletMetadata.isObject()) {
                    throw new IllegalArgumentException("wallet_metadata must be a JSON object");
                }
            } catch (IOException | IllegalArgumentException e) {
                throw new BadRequestException(
                        errorResponse(
                                Response.Status.BAD_REQUEST,
                                OAuthErrorException.INVALID_REQUEST,
                                "wallet_metadata is invalid"),
                        e);
            }
        }

        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);
        AuthenticationSessionModel authSession = recoverAuthenticationSession(requestId);

        authorizationContext = authorizationRequestService.finalizeAuthorizationRequest(
                config, authSession, authorizationContext, walletNonce, parsedWalletMetadata);

        return CorsService.open().add(Response.ok(authorizationContext.getRequestObjectJwt(), AUTH_REQ_JWT_MEDIA_TYPE));
    }

    private void validateRequestUriPostHeaders() {
        String accept = session.getContext().getRequestHeaders().getHeaderString(HttpHeaders.ACCEPT);
        if (StringUtil.isBlank(accept) || !accept.contains(AUTH_REQ_JWT_MEDIA_TYPE)) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    "Request URI POST must include Accept: " + AUTH_REQ_JWT_MEDIA_TYPE));
        }
    }

    private void validateRequestUriPostScheme() {
        URI requestUri = session.getContext().getUri().getRequestUri();
        try {
            checkUrl(session.getContext().getRealm().getSslRequired(), requestUri.toString(), "request_uri");
        } catch (IllegalArgumentException e) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    OAuthErrorException.INVALID_REQUEST,
                    "Request URI POST must use https"));
        }
    }

    /**
     * Processes authentication responses from the wallet toward user
     * authentication.
     */
    @POST
    @Path(RESPONSE_URI_PATH + "/{requestId}")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response processAuthorizationResponse(
            @PathParam("requestId") String requestId,
            @FormParam("response") String encryptedResponse,
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription,
            @FormParam(ResponseObject.VP_TOKEN_KEY) String vpToken,
            @FormParam(ResponseObject.STATE_KEY) String state) {
        logger.debug("Processing authorization response for user authentication...");

        // Recover the auth session and context given the request ID param
        AuthorizationContext authorizationContext = recoverAuthorizationContextByRequestId(requestId);
        AuthenticationSessionModel authSession = recoverAuthenticationSession(requestId);

        processAuthorizationResponse(
                authorizationContext,
                authSession,
                requestId,
                encryptedResponse,
                error,
                errorDescription,
                vpToken,
                state);

        return walletResponse(authorizationContext);
    }

    /**
     * Submits an OpenID4VP Authorization Response over the OID4VCI interactive authorization
     * (ia_post) flow, where the wallet posts the response back to the Authorization Challenge
     * Endpoint keyed by {@code transaction_id} instead of the per-request response route.
     *
     * @return the issued authorization code on success
     */
    public String submitInteractiveAuthorizationResponse(
            String transactionId,
            String encryptedResponse,
            String error,
            String errorDescription,
            String vpToken,
            String state) {
        logger.debug("Processing interactive authorization response for presentation during issuance...");

        AuthenticationSessionModel authSession = recoverAuthenticationSession(transactionId);
        AuthorizationContext authorizationContext =
                new AuthenticationSessionStore(authSession).getAuthorizationContextByTransactionId(transactionId);

        processAuthorizationResponse(
                authorizationContext,
                authSession,
                authorizationContext.getRequestId(),
                encryptedResponse,
                error,
                errorDescription,
                vpToken,
                state);

        // OID4VCI §6.2.1.1/§6.2.2: a wallet-submitted OpenID4VP error response must surface as an
        // Authorization Challenge Error Response, not as an empty successful response without a code.
        if (AuthorizationContextStatus.ERROR.equals(authorizationContext.getStatus())) {
            throw new BadRequestException(errorResponse(
                    Response.Status.BAD_REQUEST,
                    StringUtil.isNotBlank(error) ? error : OAuthErrorException.INVALID_REQUEST,
                    authorizationContext.getErrorDescription()));
        }

        return authorizationContext.getAuthorizationCode();
    }

    /**
     * Shared OpenID4VP Authorization Response processing for both the per-request response route
     * and the interactive (ia_post) challenge route.
     */
    private void processAuthorizationResponse(
            AuthorizationContext authorizationContext,
            AuthenticationSessionModel authSession,
            String requestId,
            String encryptedResponse,
            String error,
            String errorDescription,
            String vpToken,
            String state) {

        if (StringUtil.isNotBlank(error)) {
            if (StringUtil.isNotBlank(encryptedResponse) || StringUtil.isNotBlank(vpToken)) {
                throw new BadRequestException(errorResponse(
                        Response.Status.BAD_REQUEST,
                        OAuthErrorException.INVALID_REQUEST,
                        "Wallet error response must not include VP response parameters"));
            }
            try {
                validateResponseState(state, authorizationContext, requestId);
            } catch (IllegalArgumentException e) {
                throw new BadRequestException(
                        errorResponse(
                                Response.Status.BAD_REQUEST,
                                OAuthErrorException.INVALID_REQUEST,
                                String.format("Unparseable response params (%s)", e.getMessage())),
                        e);
            }
            persistWalletErrorResponse(authorizationContext, authSession, error, errorDescription);
            return;
        }

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
                    ? new ResponseObject(vpToken, state)
                    : decryptResponse(encryptedResponse, ephemeralKey, authorizationContext);

            validateResponseState(responseObject.getState(), authorizationContext, requestId);
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
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);
        AuthenticationProfile profile = config.getProfileConfig().getProfile(authorizationContext.getProfileId());

        authorizationResponseService.processAuthorizationResponse(
                responseObject, authorizationContext, authSession, authProcessor, authConfig, profile);
    }

    private void persistWalletErrorResponse(
            AuthorizationContext authorizationContext,
            AuthenticationSessionModel authSession,
            String error,
            String errorDescription) {
        String walletErrorDetails =
                StringUtil.isNotBlank(errorDescription) ? String.format("%s: %s", error, errorDescription) : error;
        authorizationContext
                .setStatus(AuthorizationContextStatus.ERROR)
                .setError(ProcessingError.WALLET_ERROR)
                .setErrorDescription(walletErrorDetails);
        new AuthenticationSessionStore(authSession).storeAuthorizationContext(authorizationContext);
    }

    private Response walletResponse(AuthorizationContext authorizationContext) {
        String responseCode = authorizationContext.getResponseCode();
        String redirectUri = StringUtil.isNotBlank(responseCode)
                ? KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                        .path(CALLBACK_URI_PATH)
                        .path(responseCode)
                        .build()
                        .toString()
                : null;
        ResponseToWallet response = new ResponseToWallet(redirectUri);
        return CorsService.open().add(Response.ok(response, MediaType.APPLICATION_JSON));
    }

    /**
     * Redirect callback to complete same-device, form authentication.
     */
    @GET
    @Path(CALLBACK_URI_PATH + "/{responseCode}")
    @Produces(MediaType.TEXT_HTML)
    public Response redirectCallback(@PathParam("responseCode") String responseCode) {
        logger.debug("Handling redirect callback for same-device authentication...");

        AuthenticationSessionModel authSession = null;
        AuthenticationSessionStore authStore;
        AuthorizationContext authContext;

        try {
            authSession = this.recoverAuthenticationSession(responseCode);
            authStore = new AuthenticationSessionStore(authSession);
            authContext = authStore.getAuthorizationContextByResponseCode(responseCode);
        } catch (IllegalArgumentException e) {
            String msg = "Authorization context not found for response code: " + responseCode;
            logger.error(msg, e);
            return ErrorPage.error(session, authSession, Response.Status.NOT_FOUND, msg);
        }

        // Check cookie-tracked session is consistent with this redirection attempt
        if (!matchesCookieTrackedAuthSession(
                authContext.getParentAuthSessionId(), Objects.requireNonNull(authContext.getLoginActionUrl()))) {
            String msg = "Authentication session does not match cookie-tracked session";
            logger.error(msg);
            return ErrorPage.error(session, authSession, Response.Status.BAD_REQUEST, msg);
        }

        // Invalidate current response code to prevent reuse.
        // The field is not voided for it is used as a marker of same-device flows.
        String newRandomResponseCode = AuthorizationRequestService.generateSessionBoundId(authSession);
        authContext.setResponseCode(newRandomResponseCode);
        authStore.storeAuthorizationContext(authContext);

        // Build redirect URI
        URI redirectUri = KeycloakUriBuilder.fromUri(authContext.getLoginActionUrl())
                .queryParam(OAuth2Constants.CODE, authContext.getAuthorizationCode())
                .build();

        // Return redirect response
        return Response.status(Response.Status.FOUND).location(redirectUri).build();
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
    public AuthorizationContext startAuthentication(
            String clientId,
            String profileId,
            OIDCAuthSession oidcAuthSession,
            CodeChallengeDetails codeChallengeDetails) {
        logger.debug("Generating new authentication context...");

        if (oidcAuthSession == null || !oidcAuthSession.enableSameDeviceResponse()) {
            validateOwnershipBinding(codeChallengeDetails);
        }

        ClientModel client = checkClient(clientId);
        AuthenticationSessionModel authSession = createAuthSession(client);
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);
        AuthenticationProfile profile = config.getProfileConfig().getProfile(profileId);

        // Call delegate service to create an authorization request
        AuthorizationContext authorizationContext = authorizationRequestService.createAuthorizationRequest(
                config, profile, authSession, oidcAuthSession, codeChallengeDetails);

        return new AuthorizationContext()
                .setAuthorizationRequest(authorizationContext.getAuthorizationRequest())
                .setTransactionId(authorizationContext.getTransactionId());
    }

    /**
     * Initializes OpenID4VP authentication for the OID4VCI interactive authorization (ia_post)
     * flow. The signed request object is embedded inline and its {@code response_uri} points to
     * the supplied Authorization Challenge Endpoint, where the wallet posts its response.
     *
     * @return an authorization context exposing the {@code transaction_id} and signed request object
     */
    public AuthorizationContext startInteractiveAuthentication(
            String clientId, String profileId, CodeChallengeDetails codeChallengeDetails, String responseUri) {
        logger.debug("Generating new interactive authentication context...");

        validateOwnershipBinding(codeChallengeDetails);

        ClientModel client = checkClient(clientId);
        AuthenticationSessionModel authSession = createAuthSession(client);
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);
        AuthenticationProfile profile = config.getProfileConfig().getProfile(profileId);

        AuthorizationContext authorizationContext = authorizationRequestService.createAuthorizationRequest(
                config,
                profile,
                authSession,
                null,
                codeChallengeDetails,
                new InteractiveResponseConfig(ResponseMode.IA_POST, responseUri));

        return new AuthorizationContext()
                .setTransactionId(authorizationContext.getTransactionId())
                .setRequestObjectJwt(authorizationContext.getRequestObjectJwt());
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

    public List<AuthenticationProfile> getAuthenticationProfilesForClient(String clientId) {
        checkClient(clientId);
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);
        return config.getProfileConfig().getProfilesForClient(clientId);
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
     *
     * @param encryptedResponse the assumed JWE encrypted response string
     * @param ephemeralKey      the ephemeral key generated for the authentication
     *                          session
     */
    private ResponseObject decryptResponse(
            String encryptedResponse, String ephemeralKey, AuthorizationContext authorizationContext) {
        try {
            AuthorizationResponseJweValidator.validate(encryptedResponse, authorizationContext);
            ECPrivateKey privKey = EphemeralKeyUtils.privateKeyFromBase64(ephemeralKey);
            String decryptedResponse = EphemeralKeyUtils.decrypt(encryptedResponse, privKey);
            return JsonSerialization.readValue(decryptedResponse, ResponseObject.class);
        } catch (JWEException | IOException e) {
            logger.error("Failed to decrypt response", e);
            throw new IllegalArgumentException("Failed to decrypt and parse response", e);
        }
    }

    /**
     * Prepares an invalid request response with the given status and error
     * description.
     */
    private Response errorResponse(Response.Status status, String error, String errorDescription) {
        var errorResponse = new OAuth2ErrorRepresentation(error, errorDescription);
        return CorsService.open()
                .add(Response.status(status).entity(errorResponse).type(MediaType.APPLICATION_JSON));
    }

    private void validateResponseState(String state, AuthorizationContext authorizationContext, String requestId) {
        ResponseStateValidator.validate(
                state, authorizationContext.getRequestObject().getDcqlQuery(), requestId);
    }

    /**
     * Validates ownership binding by requiring code challenge parameters.
     */
    private void validateOwnershipBinding(CodeChallengeDetails codeChallengeDetails) {
        if (codeChallengeDetails == null
                || StringUtil.isBlank(codeChallengeDetails.codeChallenge())
                || StringUtil.isBlank(codeChallengeDetails.codeChallengeMethod())) {
            throw new IllegalArgumentException(
                    "Authorization requests must include both code_challenge and code_challenge_method");
        }

        if (!OAuth2Constants.PKCE_METHOD_S256.equals(codeChallengeDetails.codeChallengeMethod())) {
            throw new IllegalArgumentException("Only S256 code challenge method is supported");
        }
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}
}
