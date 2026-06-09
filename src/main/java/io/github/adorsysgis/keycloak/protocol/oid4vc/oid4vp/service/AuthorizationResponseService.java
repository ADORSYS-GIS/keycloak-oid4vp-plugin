package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialClaims;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SelfTrustedSdJwtIssuer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustedSdJwtIssuer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationProcessor;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.utils.OAuth2Code;
import org.keycloak.protocol.oidc.utils.OAuth2CodeParser;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.consumer.TrustedSdJwtIssuer;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.MediaType;
import org.keycloak.utils.StringUtil;

/**
 * Dedicated service for processing OpenID4VP authorization responses for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationResponseService {

    private static final Logger logger = Logger.getLogger(AuthorizationResponseService.class);

    public static final String PARENT_AUTH_SESSION_ID = "parent_auth_session_id";

    private final KeycloakSession session;

    public AuthorizationResponseService(KeycloakSession session) {
        this.session = session;
    }

    /**
     * Processes authorization response for user authentication.
     */
    public void processAuthorizationResponse(
            ResponseObject responseObject,
            AuthorizationContext authContext,
            AuthenticationSessionModel authSession,
            AuthenticationProcessor authProcessor,
            AuthenticatorConfigModel authConfig,
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

        CredentialRequirement primaryCredential = getPrimaryCredential(profile);
        HashMap<String, String> sdJwtVpTokens = extractSdJwtVpTokens(responseObject, profile, store, authContext);
        String primarySdJwtVp = sdJwtVpTokens.get(primaryCredential.getId());
        SdJwtVP primarySdJwt = parseSdJwtVp(primarySdJwtVp, authContext, store);

        // Formally, we should then check that the VP token satisfies the DCQL constraints.
        // Equivalently, we offload this task to the SD-JWT authenticator in the authentication flow.
        logger.debugf("Initializing authentication with extracted SD-JWT VP token");
        var processorSession = authProcessor.getAuthenticationSession();
        String nonce = authContext.getRequestObject().getNonce();
        String aud = authContext.getRequestObject().getClientId();
        processorSession.setAuthNote(SdJwtAuthenticator.SDJWT_TOKEN_KEY, primarySdJwtVp);
        processorSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_NONCE_KEY, nonce);
        processorSession.setAuthNote(SdJwtAuthenticator.CHALLENGE_AUD_KEY, aud);
        try {
            processorSession.setAuthNote(
                    SdJwtAuthenticator.CREDENTIAL_REQUIREMENT_KEY,
                    JsonSerialization.writeValueAsString(primaryCredential));
        } catch (Exception e) {
            throw failWithHttpException(
                    ProcessingError.INVALID_VP_TOKEN,
                    "Invalid profile configuration",
                    "Could not serialize primary credential requirement",
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }

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

        verifySupportingCredentials(
                profile,
                sdJwtVpTokens,
                primaryCredential,
                primarySdJwt,
                clientSession.getUserSession().getUser(),
                authConfig,
                authContext,
                store);

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
     * Extract SD-JWT VP token from response object
     */
    private HashMap<String, String> extractSdJwtVpTokens(
            ResponseObject responseObject,
            AuthenticationProfile profile,
            AuthenticationSessionStore store,
            AuthorizationContext authContext) {
        var vpTokenMap = responseObject.getVpToken();
        HashMap<String, String> tokens = new HashMap<>();

        if (vpTokenMap == null) {
            failInvalidVpToken("Presented vp_token map is missing", authContext, store);
        }

        for (CredentialRequirement credential : profile.getCredentials()) {
            var credentialTokens = vpTokenMap.get(credential.getId());
            if (credentialTokens == null || credentialTokens.size() != 1) {
                String errorMsg = String.format(
                        "Presented vp_token map must contain exactly one token for credential '%s'. Found: %d",
                        credential.getId(), credentialTokens == null ? 0 : credentialTokens.size());
                failInvalidVpToken(errorMsg, authContext, store);
            }
            tokens.put(credential.getId(), decodeIfBase64Url(credentialTokens.getFirst()));
        }

        return tokens;
    }

    private SdJwtVP parseSdJwtVp(
            String sdJwtVpToken, AuthorizationContext authContext, AuthenticationSessionStore store) {
        try {
            return SdJwtVP.of(sdJwtVpToken);
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Failed to parse SD-JWT VP token");
            throw failInvalidVpToken("Could not parse SD-JWT VP token contained in `vp_token`", authContext, store);
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

    private CredentialRequirement getPrimaryCredential(AuthenticationProfile profile) {
        return profile.getCredentials().stream()
                .filter(credential -> CredentialRole.PRIMARY.equals(credential.getRole()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Profile has no primary credential: " + profile.getId()));
    }

    private void verifySupportingCredentials(
            AuthenticationProfile profile,
            HashMap<String, String> sdJwtVpTokens,
            CredentialRequirement primaryCredential,
            SdJwtVP primarySdJwt,
            UserModel user,
            AuthenticatorConfigModel authConfig,
            AuthorizationContext authContext,
            AuthenticationSessionStore store) {
        for (CredentialRequirement credential : profile.getCredentials()) {
            if (credential.getId().equals(primaryCredential.getId())) {
                continue;
            }

            SdJwtVP supportingSdJwt = verifySupportingCredential(
                    credential, sdJwtVpTokens.get(credential.getId()), authConfig, authContext, store);
            applyBindingRules(credential, supportingSdJwt, primarySdJwt, user, authContext, store);
        }
    }

    private SdJwtVP verifySupportingCredential(
            CredentialRequirement credential,
            String sdJwtVpToken,
            AuthenticatorConfigModel authConfig,
            AuthorizationContext authContext,
            AuthenticationSessionStore store) {
        SdJwtVP sdJwt = parseSdJwtVp(sdJwtVpToken, authContext, store);
        SdJwtAuthRequirements authReqs = new SdJwtAuthRequirements(session.getContext(), authConfig, credential);
        List<TrustedSdJwtIssuer> trustedIssuers = trustedIssuersFor(credential, authContext, store);

        try {
            new SdJwtPresentationConsumer()
                    .verifySdJwtPresentation(
                            sdJwt,
                            authReqs.getPresentationRequirements(),
                            trustedIssuers,
                            authReqs.getIssuerSignedJwtVerificationOpts(),
                            authReqs.getKeyBindingJwtVerificationOpts(
                                    authContext.getRequestObject().getNonce(),
                                    authContext.getRequestObject().getClientId()));

            if (authReqs.shouldEnforceRevocationStatus()) {
                new ReferencedTokenValidator(new TrustedStatusListJwtFetcher(session))
                        .validate(sdJwt.getIssuerSignedJWT().getPayload());
            }
            return sdJwt;
        } catch (VerificationException | ReferencedTokenValidationException e) {
            throw failWithHttpException(
                    ProcessingError.VP_TOKEN_AUTH_ERROR,
                    "Invalid SD-JWT presentation",
                    "Supporting credential '%s' could not be verified".formatted(credential.getId()),
                    Response.Status.UNAUTHORIZED,
                    authContext,
                    store);
        }
    }

    private List<TrustedSdJwtIssuer> trustedIssuersFor(
            CredentialRequirement credential, AuthorizationContext authContext, AuthenticationSessionStore store) {
        if (credential.getTrust() == null || credential.getTrust().isEmpty()) {
            return List.of(new SelfTrustedSdJwtIssuer(session));
        }

        List<TrustedSdJwtIssuer> trustedIssuers = credential.getTrust().stream()
                .map(trust -> trustedIssuerFor(credential, trust, authContext, store))
                .toList();
        if (trustedIssuers.isEmpty()) {
            throw failWithHttpException(
                    ProcessingError.VP_TOKEN_AUTH_ERROR,
                    "Invalid SD-JWT presentation",
                    "Credential '%s' has no supported trust policy".formatted(credential.getId()),
                    Response.Status.BAD_REQUEST,
                    authContext,
                    store);
        }
        return trustedIssuers;
    }

    private TrustedSdJwtIssuer trustedIssuerFor(
            CredentialRequirement credential,
            TrustPolicy trust,
            AuthorizationContext authContext,
            AuthenticationSessionStore store) {
        return switch (trust.getType()) {
            case TrustPolicy.SELF -> new SelfTrustedSdJwtIssuer(session);
            case TrustPolicy.EUDI_PID_TRUST_LIST -> new EudiPidTrustedSdJwtIssuer(session, trust);
            default ->
                throw failWithHttpException(
                        ProcessingError.VP_TOKEN_AUTH_ERROR,
                        "Invalid SD-JWT presentation",
                        "Credential '%s' uses an unsupported trust policy: %s"
                                .formatted(credential.getId(), trust.getType()),
                        Response.Status.BAD_REQUEST,
                        authContext,
                        store);
        };
    }

    private void applyBindingRules(
            CredentialRequirement credential,
            SdJwtVP supportingSdJwt,
            SdJwtVP primarySdJwt,
            UserModel user,
            AuthorizationContext authContext,
            AuthenticationSessionStore store) {
        for (BindingRule rule : credential.getBinding()) {
            String supportingValue = SdJwtCredentialClaims.readClaim(supportingSdJwt, rule.getCredentialClaim());
            String expectedValue =
                    switch (rule.getType()) {
                        case BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM ->
                            SdJwtCredentialClaims.readClaim(primarySdJwt, rule.getPrimaryCredentialClaim());
                        case BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE ->
                            readUserAttribute(user, rule.getUserAttribute());
                        default ->
                            throw failWithHttpException(
                                    ProcessingError.VP_TOKEN_AUTH_ERROR,
                                    "Invalid SD-JWT presentation",
                                    "Unsupported binding rule type: " + rule.getType(),
                                    Response.Status.BAD_REQUEST,
                                    authContext,
                                    store);
                    };

            if (StringUtil.isBlank(supportingValue) || !supportingValue.equals(expectedValue)) {
                throw failWithHttpException(
                        ProcessingError.VP_TOKEN_AUTH_ERROR,
                        "Invalid SD-JWT presentation",
                        "Supporting credential '%s' failed binding rule '%s'"
                                .formatted(credential.getId(), rule.getType()),
                        Response.Status.UNAUTHORIZED,
                        authContext,
                        store);
            }
        }
    }

    private String readUserAttribute(UserModel user, String userAttribute) {
        return switch (userAttribute) {
            case "given_name", "firstName" -> user.getFirstName();
            case "family_name", "lastName" -> user.getLastName();
            case "username", "preferred_username" -> user.getUsername();
            default -> user.getFirstAttribute(userAttribute);
        };
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
