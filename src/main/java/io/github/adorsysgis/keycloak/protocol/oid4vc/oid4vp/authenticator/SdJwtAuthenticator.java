package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.OID4VPProfileConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.sdjwt.consumer.SdJwtPresentationConsumer;
import org.keycloak.sdjwt.vp.KeyBindingJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Authenticate by presenting a valid SD-JWT credential.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class SdJwtAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(SdJwtAuthenticator.class);

    private final SdJwtPresentationConsumer consumer;
    private final ReferencedTokenValidator tokenStatusValidator;

    /**
     * The authenticating party is challenged to produce a presentation with a nonce.
     */
    public static final String CHALLENGE_NONCE_KEY = "nonce";

    /**
     * The authenticating party is challenged to produce a presentation with an audience.
     */
    public static final String CHALLENGE_AUD_KEY = "aud";

    /**
     * The authenticating party presents a non-replayable SD-JWT token for authentication.
     */
    public static final String SDJWT_TOKEN_KEY = "sdjwt_token";

    /**
     * Optional serialized map of DCQL credential IDs to presented SD-JWT VP tokens.
     */
    public static final String SDJWT_TOKENS_KEY = "sdjwt_tokens";

    public static final String REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY = "require_cryptographic_holder_binding";

    public static final String TRANSACTION_DATA_WIRE_KEY = "transaction_data_wire";

    public SdJwtAuthenticator(StatusListJwtFetcher statusListJwtFetcher) {
        this.consumer = new SdJwtPresentationConsumer();
        this.tokenStatusValidator = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        logger.info("Authenticating with SdJwtAuthenticator");

        AuthenticationProfile profile = getAuthenticationProfile(context);
        CredentialRequirement primaryCredential = profile.getPrimaryCredential();
        SdJwtAuthRequirements authReqs = getAuthenticationRequirements(context, primaryCredential);
        String nonce = authSession.getAuthNote(CHALLENGE_NONCE_KEY);
        String aud = authSession.getAuthNote(CHALLENGE_AUD_KEY);
        boolean requireCryptographicHolderBinding = parseRequireCryptographicHolderBinding(
                authSession.getAuthNote(REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY));
        SdJwtVP sdJwt = SdJwtVP.of(authSession.getAuthNote(SDJWT_TOKEN_KEY));

        try {
            consumer.verifySdJwtPresentation(
                    sdJwt,
                    authReqs.getPresentationRequirements(),
                    SdJwtTrustedIssuerResolver.resolve(context.getSession(), primaryCredential),
                    authReqs.getIssuerSignedJwtVerificationOpts(),
                    authReqs.getKeyBindingJwtVerificationOpts(nonce, aud, requireCryptographicHolderBinding));
        } catch (VerificationException e) {
            logger.errorf(e, "Token verification failed (authSession = %s)", correlationId(context));
            failRejectingPresentedSdJwtToken(context, e.getMessage(), e);
            return;
        }

        try {
            validateTransactionData(authSession, sdJwt);
        } catch (IllegalArgumentException e) {
            logger.errorf(e, "Transaction data validation failed (authSession = %s)", correlationId(context));
            failRejectingPresentedSdJwtToken(context, e.getMessage(), e);
            return;
        }

        // Validate token status if enforced
        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                tokenStatusValidator.validate(sdJwt.getIssuerSignedJWT().getPayload());
            } catch (ReferencedTokenValidationException e) {
                logger.errorf(e, "Token status verification failed (authSession = %s)", correlationId(context));
                failRejectingPresentedSdJwtToken(context, "Token status verification failed", e);
                return;
            }
        }

        UserModel user = recoverAuthenticatingUser(context, sdJwt);
        if (user == null) {
            return;
        }

        if (!user.isEnabled()) {
            logger.debugf("Rejecting authentication for disabled user '%s'", user.getUsername());
            failDenyingDisabledUser(context);
            return;
        }

        try {
            Map<String, String> sdJwtVpTokens = getPresentedSdJwtTokens(authSession);
            new SdJwtSupportingCredentialVerifier(context.getSession(), consumer, tokenStatusValidator)
                    .verify(
                            profile,
                            sdJwtVpTokens,
                            sdJwt,
                            user,
                            context.getAuthenticatorConfig(),
                            nonce,
                            aud,
                            requireCryptographicHolderBinding);
        } catch (VerificationException | IllegalStateException e) {
            logger.errorf(e, "Supporting credential verification failed (authSession = %s)", correlationId(context));
            failRejectingPresentedSdJwtToken(context, e.getMessage(), e);
            return;
        }

        context.setUser(user);
        context.success(); // Mark authentication as successful
        logger.debugf("User '%s' successfully authenticated", user.getUsername());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form action is relevant for this authenticator
    }

    private SdJwtAuthRequirements getAuthenticationRequirements(
            AuthenticationFlowContext context, CredentialRequirement primaryCredential) {
        if (!primaryCredential.isPrimary()) {
            throw new IllegalStateException("Authentication profile primary credential is invalid");
        }
        return new SdJwtAuthRequirements(
                context.getSession().getContext(), context.getAuthenticatorConfig(), primaryCredential);
    }

    private AuthenticationProfile getAuthenticationProfile(AuthenticationFlowContext context) {
        OID4VPProfileConfig profileConfig =
                new OID4VPProfileConfig(context.getSession().getContext(), context.getAuthenticatorConfig());
        AuthenticationSessionStore store = new AuthenticationSessionStore(context.getAuthenticationSession());
        if (!store.hasAuthorizationContext()) {
            return profileConfig.getProfile(AuthenticationProfile.DEFAULT_PROFILE_ID);
        }

        AuthorizationContext authContext = store.getAuthorizationContext();
        return profileConfig.getProfile(authContext.getProfileId());
    }

    private Map<String, String> getPresentedSdJwtTokens(AuthenticationSessionModel authSession) {
        String tokensJson = authSession.getAuthNote(SDJWT_TOKENS_KEY);
        if (StringUtil.isBlank(tokensJson)) {
            return Map.of();
        }
        try {
            return JsonSerialization.readValue(tokensJson, new TypeReference<Map<String, String>>() {});
        } catch (IOException e) {
            throw new IllegalStateException("Invalid SD-JWT tokens auth note", e);
        }
    }

    private static boolean parseRequireCryptographicHolderBinding(String note) {
        if (StringUtil.isBlank(note)) {
            return true;
        }
        return Boolean.parseBoolean(note);
    }

    void validateTransactionData(AuthenticationSessionModel authSession, SdJwtVP sdJwt) {
        String wireJson = authSession.getAuthNote(TRANSACTION_DATA_WIRE_KEY);
        if (StringUtil.isBlank(wireJson)) {
            return;
        }

        List<String> transactionDataWire;
        try {
            transactionDataWire = JsonSerialization.readValue(wireJson, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid transaction_data session state", e);
        }

        Optional<KeyBindingJWT> keyBindingJwt = sdJwt.getKeyBindingJWT();
        if (keyBindingJwt.isEmpty()) {
            throw new IllegalArgumentException("Key Binding JWT required when transaction_data is requested");
        }

        ObjectNode kbPayload = keyBindingJwt.get().getPayload();
        TransactionDataValidator.validate(transactionDataWire, kbPayload);
    }

    private UserModel recoverAuthenticatingUser(AuthenticationFlowContext context, SdJwtVP sdJwt) {
        logger.info("Recovering authenticating user");

        String subject = readSubjectFromCredential(sdJwt);
        if (StringUtil.isBlank(subject)) {
            logger.warn("Presented SD-JWT is missing subject claim");
        } else {
            logger.debugf("Presented subject: %s", subject);
        }

        String presentedUsername = readUsernameFromCredential(sdJwt);
        if (StringUtil.isBlank(presentedUsername)) {
            logger.warn("Presented SD-JWT is missing required username claim");
            failRejectingPresentedSdJwtToken(context, "Missing username claim");
            return null;
        }

        UserModel user = null;
        if (!StringUtil.isBlank(subject)) {
            user = context.getSession().users().getUserById(context.getRealm(), subject);
            if (user != null) {
                logger.debugf("Resolved user id: %s", user.getId());
            }
        }

        if (user == null) {
            // TODO: Remove username-only fallback once SubjectID mapper is fixed and stable.
            logger.warn("Subject did not resolve to a user. Falling back to username lookup.");
            user = context.getSession().users().getUserByUsername(context.getRealm(), presentedUsername);
        }

        if (user == null) {
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(context);
            return null;
        }

        if (!presentedUsername.equals(user.getUsername())) {
            logger.warnf(
                    "Username mismatch for subject '%s': credential='%s', user='%s'",
                    subject, presentedUsername, user.getUsername());
            failRejectingPresentedSdJwtToken(context, "Username mismatch");
            return null;
        }

        return user;
    }

    private String readSubjectFromCredential(SdJwtVP sdJwt) {
        return readClaimFromCredential(sdJwt, JsonWebToken.SUBJECT);
    }

    private String readUsernameFromCredential(SdJwtVP sdJwt) {
        return readClaimFromCredential(sdJwt, OAuth2Constants.USERNAME);
    }

    private String readClaimFromCredential(SdJwtVP sdJwt, String claimName) {
        return SdJwtCredentialClaims.readClaim(sdJwt, claimName);
    }

    private static String correlationId(AuthenticationFlowContext context) {
        return ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
    }

    private void failRejectingPresentedSdJwtToken(AuthenticationFlowContext context, String reason) {
        failRejectingPresentedSdJwtToken(context, reason, null);
    }

    private void failRejectingPresentedSdJwtToken(AuthenticationFlowContext context, String reason, Throwable cause) {
        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        if (cause != null) {
            logger.errorf(cause, "Presented SD-JWT rejected (authSession = %s): %s", correlationId, reason);
        } else {
            logger.errorf("Presented SD-JWT rejected (authSession = %s): %s", correlationId, reason);
        }

        String description = String.format("Invalid SD-JWT presentation (%s)", reason);
        var errorRep = new OAuth2ErrorRepresentation(Errors.INVALID_USER_CREDENTIALS, description);

        context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingAuthenticatingUser(AuthenticationFlowContext context) {
        logger.info("Presented SD-JWT will be rejected for associated user is unknown");

        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        logger.errorf("User with presented SD-JWT is unknown (authSession = %s)", correlationId);

        String description = "User with presented SD-JWT is unknown";

        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_NOT_FOUND, description);

        context.failure(
                AuthenticationFlowError.UNKNOWN_USER,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingDisabledUser(AuthenticationFlowContext context) {
        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_DISABLED, "User with presented SD-JWT is disabled");

        context.failure(
                AuthenticationFlowError.USER_DISABLED,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

    @Override
    public void close() {}
}
