package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.CodeChallengeDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.CorsService;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.OPTIONS;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.urls.UrlType;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * OID4VCI Interactive Authorization challenge endpoint
 * (OID4VCI §6, OAuth 2.0 for First-Party Apps).
 *
 * <p>On a missing/insufficient presentation the endpoint starts an OID4VP request
 * and returns {@code 401 insufficient_authorization} with {@code interaction_type_required},
 * {@code openid4vp_request} and an {@code auth_session} the wallet resumes.
 */
public class AuthorizationChallengeEndpoint extends OID4VPUserAuthEndpointBase implements RealmResourceProvider {

    private static final Logger logger = Logger.getLogger(AuthorizationChallengeEndpoint.class);

    public static final String ERROR_INSUFFICIENT_AUTHORIZATION = "insufficient_authorization";
    public static final String ERROR_MISSING_INTERACTION_TYPE = "missing_interaction_type";
    public static final String INTERACTION_OPENID4VP_PRESENTATION = "urn:openid:dcp:ia:openid4vp_presentation";
    public static final String PROFILE_ID_PARAM = "profile_id";
    public static final String AUTH_SESSION_PARAM = "auth_session";
    public static final String OPENID4VP_RESPONSE_PARAM = "openid4vp_response";
    public static final String INTERACTION_TYPES_SUPPORTED_PARAM = "interaction_types_supported";
    public static final String WWW_AUTHENTICATE_CHALLENGE = "Bearer error=\"insufficient_authorization\"";

    private final OID4VPUserAuthEndpoint oid4vpAuth;

    public AuthorizationChallengeEndpoint(KeycloakSession session, EventBuilder event) {
        super(session, event);
        this.oid4vpAuth = new OID4VPUserAuthEndpoint(session, event);
    }

    @OPTIONS
    @Path("{any:.*}")
    public Response preflight() {
        return CorsService.openPreflight().add(Response.ok());
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response challenge(
            @FormParam(OAuth2Constants.CLIENT_ID) String clientId,
            @FormParam(PROFILE_ID_PARAM) String profileId,
            @FormParam(OAuth2Constants.CODE_CHALLENGE) String codeChallenge,
            @FormParam(OAuth2Constants.CODE_CHALLENGE_METHOD) String codeChallengeMethod,
            @FormParam(OAuth2Constants.SCOPE) String scope,
            @FormParam(OAuth2Constants.AUTHORIZATION_DETAILS) String authorizationDetails,
            @FormParam(OAuth2Constants.ISSUER_STATE) String issuerState,
            @FormParam(INTERACTION_TYPES_SUPPORTED_PARAM) String interactionTypesSupported,
            @FormParam(OPENID4VP_RESPONSE_PARAM) String openid4vpResponse,
            @FormParam(AUTH_SESSION_PARAM) String authSession) {

        if (StringUtil.isNotBlank(openid4vpResponse)) {
            return submitPresentation(authSession, openid4vpResponse);
        }
        if (StringUtil.isNotBlank(authSession)) {
            return resumeChallenge(authSession);
        }
        return initiateChallenge(
                clientId,
                profileId,
                codeChallenge,
                codeChallengeMethod,
                scope,
                authorizationDetails,
                issuerState,
                interactionTypesSupported);
    }

    private Response initiateChallenge(
            String clientId,
            String profileId,
            String codeChallenge,
            String codeChallengeMethod,
            String scope,
            String authorizationDetails,
            String issuerState,
            String interactionTypesSupported) {
        logger.debug("Issuing authorization challenge for presentation during issuance...");

        if (!supportsPresentation(interactionTypesSupported)) {
            throw missingInteractionType();
        }

        AuthorizationContext authContext;
        try {
            authContext = oid4vpAuth.startInteractiveAuthentication(
                    clientId,
                    profileId,
                    new CodeChallengeDetails(codeChallenge, codeChallengeMethod),
                    challengeResponseUri());
        } catch (IllegalArgumentException e) {
            throw badRequest(e.getMessage());
        }

        // Propagate OID4VCI authorization so the token grant emits authorization_details.
        bindCredentialAuthorization(authContext.getTransactionId(), scope, authorizationDetails, issuerState);

        AuthorizationChallengeResponse body = new AuthorizationChallengeResponse(
                        ERROR_INSUFFICIENT_AUTHORIZATION, authContext.getTransactionId())
                .setInteractionTypeRequired(INTERACTION_OPENID4VP_PRESENTATION)
                .setOpenid4vpRequest(toOpenid4vpRequest(authContext.getRequestObjectJwt()));

        return challengeResponse(body);
    }

    /** Wraps the signed OpenID4VP request object as a JSON object (OID4VCI §6.2.1.1). */
    private JsonNode toOpenid4vpRequest(String requestObjectJwt) {
        ObjectNode node = JsonSerialization.mapper.createObjectNode();
        node.put("request", requestObjectJwt);
        return node;
    }

    /** Resolves the Authorization Challenge Endpoint URI used as the OpenID4VP {@code response_uri}. */
    private String challengeResponseUri() {
        String realmUrl =
                Urls.realmIssuer(session.getContext().getUri(UrlType.FRONTEND).getBaseUri(), realm.getName());
        return KeycloakUriBuilder.fromUri(realmUrl)
                .path(AuthorizationChallengeEndpointFactory.PROVIDER_ID)
                .build()
                .toString();
    }

    private boolean supportsPresentation(String interactionTypesSupported) {
        if (StringUtil.isBlank(interactionTypesSupported)) {
            return false;
        }
        for (String type : interactionTypesSupported.split(",")) {
            if (INTERACTION_OPENID4VP_PRESENTATION.equals(type.trim())) {
                return true;
            }
        }
        return false;
    }

    private void bindCredentialAuthorization(
            String transactionId, String scope, String authorizationDetails, String issuerState) {
        if (StringUtil.isBlank(scope) && StringUtil.isBlank(authorizationDetails) && StringUtil.isBlank(issuerState)) {
            throw badRequest("Either scope, authorization_details or issuer_state is required");
        }
        AuthenticationSessionModel authSession = getAuthSession(pruneAuthSessionId(transactionId))
                .orElseThrow(() -> badRequest("Authorization session not found"));
        if (StringUtil.isNotBlank(scope)) {
            authSession.setClientNote(OAuth2Constants.SCOPE, scope);
        }
        if (StringUtil.isNotBlank(authorizationDetails)) {
            authSession.setClientNote(OAuth2Constants.AUTHORIZATION_DETAILS, authorizationDetails);
        }
        // Mirror the standard Authorization Endpoint so the token grant can resolve the credential offer
        // (OID4VCAuthorizationDetailsProcessor reads issuer_state from this client-session note).
        if (StringUtil.isNotBlank(issuerState)) {
            authSession.setClientNote(
                    AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX
                            + OAuth2Constants.ISSUER_STATE,
                    issuerState);
        }
    }

    /**
     * Binds the wallet's presentation to the challenge session. Presentation
     * processing itself runs over the existing OID4VP response routes.
     */
    private Response resumeChallenge(String authSession) {
        logger.debug("Resuming authorization challenge for presentation during issuance...");

        AuthorizationContext context = lookupContext(authSession);
        AuthorizationContextStatus status = context.getStatus();
        if (AuthorizationContextStatus.ERROR.equals(status)) {
            throw badRequest("Presentation during issuance failed");
        }
        if (!AuthorizationContextStatus.SUCCESS.equals(status)) {
            return reChallenge(authSession);
        }

        // SUCCESS: presentation bound, issue the authorization_code.
        AuthorizationChallengeResponse body =
                new AuthorizationChallengeResponse().setAuthorizationCode(context.getAuthorizationCode());
        return CorsService.open().add(Response.ok(body));
    }

    private Response reChallenge(String authSession) {
        AuthorizationChallengeResponse body = new AuthorizationChallengeResponse(
                        ERROR_INSUFFICIENT_AUTHORIZATION, authSession)
                .setInteractionTypeRequired(INTERACTION_OPENID4VP_PRESENTATION);
        return challengeResponse(body);
    }

    /**
     * Processes the wallet's OpenID4VP Authorization Response submitted natively to this endpoint
     * (response_mode=ia_post) and issues the authorization_code on success.
     */
    private Response submitPresentation(String authSession, String openid4vpResponse) {
        logger.debug("Processing OpenID4VP response submitted to the authorization challenge endpoint...");

        if (StringUtil.isBlank(authSession)) {
            throw badRequest("auth_session is required when submitting openid4vp_response");
        }

        OpenID4VPResponse response = parseOpenid4vpResponse(openid4vpResponse);
        String authorizationCode = oid4vpAuth.submitInteractiveAuthorizationResponse(
                authSession,
                response.encryptedResponse(),
                response.error(),
                response.errorDescription(),
                response.vpToken(),
                response.state());

        AuthorizationChallengeResponse body =
                new AuthorizationChallengeResponse().setAuthorizationCode(authorizationCode);
        return CorsService.open().add(Response.ok(body));
    }

    private OpenID4VPResponse parseOpenid4vpResponse(String openid4vpResponse) {
        JsonNode node;
        try {
            node = JsonSerialization.mapper.readTree(openid4vpResponse);
        } catch (IOException e) {
            throw badRequest("openid4vp_response is not valid JSON");
        }
        if (node == null || !node.isObject()) {
            throw badRequest("openid4vp_response must be a JSON object");
        }

        // vp_token keeps its JSON shape so it can be parsed into the wire-level token map downstream.
        String vpToken = node.hasNonNull("vp_token") ? node.get("vp_token").toString() : null;
        String encryptedResponse = textOrNull(node, "response");
        String state = textOrNull(node, ResponseObject.STATE_KEY);
        String error = textOrNull(node, OAuth2Constants.ERROR);
        String errorDescription = textOrNull(node, OAuth2Constants.ERROR_DESCRIPTION);

        if (vpToken == null && encryptedResponse == null && error == null) {
            throw badRequest("openid4vp_response must contain at least vp_token, response, or error");
        }

        return new OpenID4VPResponse(vpToken, encryptedResponse, state, error, errorDescription);
    }

    private static String textOrNull(JsonNode node, String field) {
        return node.hasNonNull(field) ? node.get(field).asText() : null;
    }

    private record OpenID4VPResponse(
            String vpToken, String encryptedResponse, String state, String error, String errorDescription) {}

    private Response challengeResponse(AuthorizationChallengeResponse body) {
        return CorsService.open()
                .add(Response.status(Response.Status.UNAUTHORIZED)
                        .header(HttpHeaders.WWW_AUTHENTICATE, WWW_AUTHENTICATE_CHALLENGE)
                        .entity(body));
    }

    private AuthorizationContext lookupContext(String transactionId) {
        AuthenticationSessionModel authSession =
                getAuthSession(pruneAuthSessionId(transactionId)).orElseThrow(() -> badRequest("Unknown auth_session"));
        return new AuthenticationSessionStore(authSession).getAuthorizationContextByTransactionId(transactionId);
    }

    private BadRequestException missingInteractionType() {
        var error = new OAuth2ErrorRepresentation(
                ERROR_MISSING_INTERACTION_TYPE,
                "interaction_types_supported must include " + INTERACTION_OPENID4VP_PRESENTATION);
        return new BadRequestException(CorsService.open()
                .add(Response.status(Response.Status.BAD_REQUEST).entity(error).type(MediaType.APPLICATION_JSON)));
    }

    private BadRequestException badRequest(String description) {
        var error = new OAuth2ErrorRepresentation(OAuthErrorException.INVALID_REQUEST, description);
        return new BadRequestException(CorsService.open()
                .add(Response.status(Response.Status.BAD_REQUEST).entity(error).type(MediaType.APPLICATION_JSON)));
    }

    @Override
    public Object getResource() {
        return this;
    }

    @Override
    public void close() {}
}
