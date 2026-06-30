package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher.PidData;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher.PidMatcherProvider;
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
import java.util.HashMap;
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
     * Serialized map of DCQL credential IDs to presented SD-JWT VP tokens.
     */
    public static final String SDJWT_TOKENS_KEY = "sdjwt_tokens";

    public static final String REQUIRE_CRYPTOGRAPHIC_HOLDER_BINDING_KEY = "require_cryptographic_holder_binding";

    public static final String TRANSACTION_DATA_WIRE_KEY = "transaction_data_wire";

    /**
     * Marks the authentication session as an OID4VCI "presentation during issuance" flow. Only set by
     * the Authorization Challenge Endpoint; PID matching is enforced exclusively when this is present.
     */
    public static final String PRESENTATION_DURING_ISSUANCE_KEY = "presentation_during_issuance";

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

        Map<String, String> sdJwtVpTokens = getPresentedSdJwtTokens(authSession);
        String primaryToken = sdJwtVpTokens.get(primaryCredential.getId());
        if (StringUtil.isBlank(primaryToken)) {
            failRejectingPresentedSdJwtToken(
                    context, "Missing SD-JWT presentation for credential: " + primaryCredential.getId());
            return;
        }
        SdJwtVP sdJwt = SdJwtVP.of(primaryToken);

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
            new SdJwtSupportingCredentialVerifier(context.getSession(), consumer, tokenStatusValidator)
                    .verify(
                            profile,
                            supportingSdJwtVpTokens(sdJwtVpTokens, primaryCredential.getId()),
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

        if (!enforcePidMatch(context, sdJwt, user)) {
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

    private static Map<String, String> supportingSdJwtVpTokens(
            Map<String, String> presentedTokens, String primaryCredentialId) {
        Map<String, String> supportingTokens = new HashMap<>();
        presentedTokens.forEach((credentialId, token) -> {
            if (!primaryCredentialId.equals(credentialId)) {
                supportingTokens.put(credentialId, token);
            }
        });
        return supportingTokens;
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

    /**
     * Identity gate for "presentation during issuance": when a {@link PidMatcherProvider} is
     * deployed, the presented PID is matched against the brokered user's registration data and the
     * flow only continues on a full match.
     *
     * <p>Matching applies exclusively to the presentation-during-issuance flow (marked via
     * {@link #PRESENTATION_DURING_ISSUANCE_KEY}); standalone OID4VP logins are never gated.
     *
     * <p>When no matcher is installed, behaviour depends on the {@code pidMatchRequired} authenticator
     * config flag: if {@code true}, the flow fails closed (guards against a misconfigured deployment
     * that is missing the matcher plugin); if {@code false} (default), matching is skipped.
     *
     * @return {@code true} to continue; {@code false} when the flow has already been failed
     */
    boolean enforcePidMatch(AuthenticationFlowContext context, SdJwtVP sdJwt, UserModel user) {
        if (!Boolean.parseBoolean(context.getAuthenticationSession().getAuthNote(PRESENTATION_DURING_ISSUANCE_KEY))) {
            return true;
        }

        PidMatcherProvider matcher = context.getSession().getProvider(PidMatcherProvider.class);
        if (matcher == null) {
            if (Boolean.parseBoolean(config(
                    context,
                    SdJwtAuthenticatorFactory.PID_MATCH_REQUIRED_CONFIG,
                    String.valueOf(SdJwtAuthenticatorFactory.PID_MATCH_REQUIRED_CONFIG_DEFAULT)))) {
                logger.errorf(
                        "PID matching is required but no matcher provider is deployed (authSession = %s)",
                        correlationId(context));
                failRejectingPresentedSdJwtToken(context, "PID matching is required but not available");
                return false;
            }
            return true;
        }

        PidData presented = new PidData(
                SdJwtCredentialClaims.readClaim(
                        sdJwt,
                        config(
                                context,
                                SdJwtAuthenticatorFactory.PID_MATCH_GIVEN_NAME_CLAIM_CONFIG,
                                SdJwtAuthenticatorFactory.PID_MATCH_GIVEN_NAME_CLAIM_CONFIG_DEFAULT)),
                SdJwtCredentialClaims.readClaim(
                        sdJwt,
                        config(
                                context,
                                SdJwtAuthenticatorFactory.PID_MATCH_FAMILY_NAME_CLAIM_CONFIG,
                                SdJwtAuthenticatorFactory.PID_MATCH_FAMILY_NAME_CLAIM_CONFIG_DEFAULT)),
                SdJwtCredentialClaims.readClaim(
                        sdJwt,
                        config(
                                context,
                                SdJwtAuthenticatorFactory.PID_MATCH_BIRTH_DATE_CLAIM_CONFIG,
                                SdJwtAuthenticatorFactory.PID_MATCH_BIRTH_DATE_CLAIM_CONFIG_DEFAULT)));
        PidData registered = new PidData(
                user.getFirstName(),
                user.getLastName(),
                user.getFirstAttribute(config(
                        context,
                        SdJwtAuthenticatorFactory.PID_MATCH_BIRTH_DATE_ATTRIBUTE_CONFIG,
                        SdJwtAuthenticatorFactory.PID_MATCH_BIRTH_DATE_ATTRIBUTE_CONFIG_DEFAULT)));

        List<String> mismatches = matcher.findMismatchedAttributes(presented, registered);
        if (!mismatches.isEmpty()) {
            // Only attribute identifiers are logged, never the personal values (PII).
            logger.errorf(
                    "PID match failed (authSession = %s): mismatching attributes %s",
                    correlationId(context), mismatches);
            failRejectingPresentedSdJwtToken(context, "PID does not match the registered user");
            return false;
        }
        return true;
    }

    private static String config(AuthenticationFlowContext context, String key, String defaultValue) {
        var config = context.getAuthenticatorConfig();
        if (config == null || config.getConfig() == null) {
            return defaultValue;
        }
        String value = config.getConfig().get(key);
        return value != null && !value.isBlank() ? value : defaultValue;
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
