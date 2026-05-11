package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import com.apicatalog.jsonld.StringUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.CodeChallengeDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
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
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.security.interfaces.ECPrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwk.JWK;
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
    public static final String CALLBACK_URI_PATH = "/callback";
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
            authContext =
                    startAuthentication(clientId, null, new CodeChallengeDetails(codeChallenge, codeChallengeMethod));
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
            @FormParam(OAuth2Constants.ERROR) String error,
            @FormParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription,
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
        boolean hasWalletError = StringUtils.isNotBlank(error);

        if (expectsEncrypted && !hasEncrypted && hasWalletError) {
            if (StringUtils.isNotBlank(state) && !requestId.equals(state)) {
                throw new BadRequestException(errorResponse(
                        Response.Status.BAD_REQUEST,
                        OAuthErrorException.INVALID_REQUEST,
                        String.format("State param must match requestId. requestId: %s, state: %s", requestId, state)));
            }

            String walletErrorDescription =
                    StringUtils.isBlank(errorDescription) ? error : String.format("%s: %s", error, errorDescription);

            authorizationContext
                    .setStatus(AuthorizationContextStatus.ERROR)
                    .setError(ProcessingError.VP_TOKEN_AUTH_ERROR)
                    .setErrorDescription("Wallet returned error: " + walletErrorDescription);
            new AuthenticationSessionStore(authSession).storeAuthorizationContext(authorizationContext);
            return CorsService.open().add(Response.ok(Map.of()));
        }

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
                    : decryptResponse(encryptedResponse, ephemeralKey, authorizationContext);

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

        // Successful. Build redirect URI if response code attached to context, meaning same device.
        String responseCode = authorizationContext.getResponseCode();
        String redirectUri = StringUtil.isNotBlank(responseCode)
                ? KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                        .path(CALLBACK_URI_PATH)
                        .path(responseCode)
                        .build()
                        .toString()
                : null;

        // Prompts wallet to redirect if same device, or returns empty object.
        ResponseToWallet response = new ResponseToWallet(redirectUri);
        return CorsService.open().add(Response.ok(response));
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
            String clientId, OIDCAuthSession oidcAuthSession, CodeChallengeDetails codeChallengeDetails) {
        logger.debug("Generating new authentication context...");

        if (oidcAuthSession == null) {
            // Require code challenge details for API-initiated authentication sessions
            validateOwnershipBinding(codeChallengeDetails);
        }

        ClientModel client = checkClient(clientId);
        AuthenticationSessionModel authSession = createAuthSession(client);
        AuthenticatorConfigModel authConfig = getSdjwtAuthenticatorConfig();
        VerifierConfig config = new VerifierConfig(session.getContext(), authConfig);

        // Call delegate service to create an authorization request
        AuthorizationContext authorizationContext = authorizationRequestService.createAuthorizationRequest(
                config, authSession, oidcAuthSession, codeChallengeDetails);

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
    private ResponseObject decryptResponse(
            String encryptedResponse, String ephemeralKey, AuthorizationContext authorizationContext) {
        try {
            validateJweProtectedHeader(encryptedResponse, authorizationContext);
            ECPrivateKey privKey = EphemeralKeyUtils.privateKeyFromBase64(ephemeralKey);
            String decryptedResponse = EphemeralKeyUtils.decrypt(encryptedResponse, privKey);
            return JsonSerialization.readValue(decryptedResponse, ResponseObject.class);
        } catch (JWEException | IOException e) {
            logger.error("Failed to decrypt response", e);
            throw new IllegalArgumentException("Failed to decrypt and parse response", e);
        }
    }

    /**
     * Validate JWE protected header according to verifier metadata policy.
     */
    private static void validateJweProtectedHeader(String encryptedResponse, AuthorizationContext authorizationContext)
            throws IOException {
        String[] parts = encryptedResponse.split("\\.");
        if (parts.length != 5) {
            throw new IllegalArgumentException("Encrypted response is not a compact JWE");
        }

        byte[] decodedHeader = Base64.getUrlDecoder().decode(parts[0]);
        JsonNode jweHeader = JsonSerialization.mapper.readTree(decodedHeader);
        String alg = getTextClaim(jweHeader, "alg");
        String enc = getTextClaim(jweHeader, "enc");
        String kid = getTextClaim(jweHeader, "kid");

        if (alg == null || enc == null) {
            throw new IllegalArgumentException("jwe_header_invalid: missing alg or enc");
        }

        var clientMetadata = authorizationContext.getRequestObject().getClientMetadata();
        List<String> allowedAlgs = resolveAllowedAlgs();
        if (!allowedAlgs.contains(alg)) {
            throw new IllegalArgumentException("jwe_alg_unsupported: " + alg);
        }

        List<String> allowedEnc = resolveAllowedEnc(clientMetadata);
        if (!allowedEnc.contains(enc)) {
            throw new IllegalArgumentException("jwe_enc_unsupported: " + enc);
        }

        JWK[] keys = resolveEncryptionKeys(clientMetadata);
        if (keys == null || keys.length == 0) {
            throw new IllegalArgumentException("jwe_key_unavailable");
        }
        String expectedKid = authorizationContext.getExpectedEncryptionKid();
        if (kid == null) {
            throw new IllegalArgumentException("jwe_kid_missing");
        }
        if (expectedKid != null && !expectedKid.equals(kid)) {
            throw new IllegalArgumentException("jwe_kid_mismatch");
        }

        // Resolve selected key by KID only.
        JWK selectedKey = resolveSelectedKey(keys, kid);

        // Envelope consistency: if selected JWK declares alg, it must match JWE header alg
        String keyAlg = selectedKey.getAlgorithm();
        if (keyAlg != null && !keyAlg.equals(alg)) {
            throw new IllegalArgumentException("jwe_alg_key_mismatch");
        }
    }

    private static List<String> resolveAllowedAlgs() {
        // The OID4VP spec defines encrypted_response_enc_values_supported in client_metadata, but not
        // encrypted_response_alg_values_supported. We enforce our supported key management algs server-side.
        return List.of(JWEConstants.ECDH_ES);
    }

    private static List<String> resolveAllowedEnc(ClientMetadata clientMetadata) {
        List<String> allowedEnc =
                clientMetadata != null ? clientMetadata.getEncryptedResponseEncValuesSupported() : null;
        // Use the spec default when verifier did not explicitly advertise supported enc values.
        return (allowedEnc == null || allowedEnc.isEmpty()) ? List.of(JWEConstants.A128GCM) : allowedEnc;
    }

    private static JWK[] resolveEncryptionKeys(ClientMetadata clientMetadata) {
        if (clientMetadata == null || clientMetadata.getJwks() == null) {
            return null;
        }
        return clientMetadata.getJwks().getKeys();
    }

    private static JWK resolveSelectedKey(JWK[] keys, String expectedKid) {
        for (JWK key : keys) {
            if (expectedKid.equals(key.getKeyId())) {
                return key;
            }
        }
        throw new IllegalArgumentException("jwe_key_unavailable");
    }

    private static String getTextClaim(JsonNode node, String claimName) {
        JsonNode claim = node.get(claimName);
        return claim != null && claim.isTextual() ? claim.asText() : null;
    }

    /**
     * Prepares an invalid request response with the given status and error description.
     */
    private Response errorResponse(Response.Status status, String error, String errorDescription) {
        var errorResponse = new OAuth2ErrorRepresentation(error, errorDescription);
        return CorsService.open()
                .add(Response.status(status).entity(errorResponse).type(MediaType.APPLICATION_JSON));
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
