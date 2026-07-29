package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.BindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.OID4VPProfileConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;
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
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Authenticator that authenticates users via OpenID4VP presentation of verifiable credentials.
 *
 * <p>Format-specific verification (signature, holder binding, claim requirements, revocation,
 * transaction data) is delegated to a registered {@link CredentialVerifier}. The orchestrator
 * resolves the user from the credential subject and orchestrates supporting credential checks.
 *
 * <p>Multiple credential formats can be supported concurrently by registering additional handlers
 * in {@link OID4VPAuthenticatorFactory}.
 */
public class OID4VPAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(OID4VPAuthenticator.class);

    private final Map<String, CredentialVerifier> handlers;

    /**
     * Serialized map of DCQL credential IDs to presented OID4VP credential tokens.
     */
    public static final String PRESENTED_TOKENS_KEY = "presented_tokens";

    public OID4VPAuthenticator(Map<String, CredentialVerifier> handlers) {
        this.handlers = handlers;
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        logger.info("Authenticating with OID4VPAuthenticator");

        AuthenticationProfile profile = getAuthenticationProfile(context);
        CredentialRequirement primaryCredential = profile.getPrimaryCredential();

        AuthorizationContext authContext = getAuthorizationContext(authSession);
        AuthRequirements authRequirements = new AuthRequirements(context.getAuthenticatorConfig());

        Map<String, String> presentedTokens = getPresentedTokens(authSession);
        String primaryToken = presentedTokens.get(primaryCredential.getId());
        if (StringUtil.isBlank(primaryToken)) {
            failRejectingPresentedCredential(
                    context,
                    String.format("Missing credential presentation for credential: %s", primaryCredential.getId()));
            return;
        }

        CredentialVerifier primaryVerifier = resolveVerifier(authSession, primaryCredential.getId());
        JsonNode primaryClaims;

        try {
            primaryClaims = primaryVerifier.verifyCredential(
                    context, authContext, authRequirements, primaryCredential, primaryToken);
            primaryVerifier.validateTransactionData(authContext, primaryToken);
        } catch (VerificationException e) {
            logger.errorf(e, "Primary credential verification failed (authSession = %s)", correlationId(context));
            failRejectingPresentedCredential(context, e.getMessage(), e);
            return;
        }

        UserModel user =
                recoverAuthenticatingUser(context, authContext, primaryCredential, primaryVerifier, primaryClaims);
        if (user == null) {
            return;
        }

        if (!user.isEnabled()) {
            logger.debugf("Rejecting authentication for disabled user '%s'", user.getUsername());
            failDenyingDisabledUser(context);
            return;
        }

        // Primary-credential binding rules establish that the verified credential belongs to the
        // recovered Keycloak user. This is especially important for session-identity profiles, where
        // the user comes from the issuance session rather than from identity claims in the credential.
        try {
            applyBindingRules(context, primaryCredential, primaryVerifier, primaryClaims, null, null, user);
        } catch (VerificationException | IllegalStateException e) {
            logger.errorf(e, "Primary credential binding failed (authSession = %s)", correlationId(context));
            failRejectingPresentedCredential(context, e.getMessage(), e);
            return;
        }

        try {
            var supportingTokens = supportingPresentedTokens(presentedTokens, primaryCredential.getId());
            verifySupportingCredentials(
                    context,
                    authContext,
                    authSession,
                    profile,
                    primaryVerifier,
                    primaryClaims,
                    supportingTokens,
                    user,
                    authRequirements);
        } catch (VerificationException | IllegalStateException e) {
            logger.errorf(e, "Supporting credential verification failed (authSession = %s)", correlationId(context));
            failRejectingPresentedCredential(context, e.getMessage(), e);
            return;
        }

        context.setUser(user);
        context.success();
        logger.debugf("User '%s' successfully authenticated", user.getUsername());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form action is relevant for this authenticator
    }

    private CredentialVerifier resolveVerifier(AuthenticationSessionModel authSession, String credentialId) {
        DcqlQuery dcqlQuery =
                getAuthorizationContext(authSession).getRequestObject().getDcqlQuery();
        if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
            throw new IllegalStateException("No DCQL query found in authorization context");
        }

        String format = dcqlQuery.getCredentials().stream()
                .filter(c -> credentialId.equals(c.getId()))
                .map(Credential::getFormat)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(
                        String.format("Credential '%s' not found in DCQL query", credentialId)));

        CredentialVerifier verifier = handlers.get(format);
        if (verifier == null) {
            throw new IllegalStateException(String.format(
                    "No registered verifier supports format '%s' for credential '%s'", format, credentialId));
        }

        return verifier;
    }

    private void verifySupportingCredentials(
            AuthenticationFlowContext context,
            AuthorizationContext authContext,
            AuthenticationSessionModel authSession,
            AuthenticationProfile profile,
            CredentialVerifier primaryVerifier,
            JsonNode primaryClaims,
            Map<String, String> supportingTokens,
            UserModel user,
            AuthRequirements authRequirements)
            throws VerificationException {

        for (CredentialRequirement credential : profile.getCredentials()) {
            if (credential.isPrimary()) {
                continue;
            }

            String token = supportingTokens.get(credential.getId());
            if (StringUtil.isBlank(token)) {
                throw new VerificationException(String.format(
                        "Supporting credential '%s' is missing from the presentation", credential.getId()));
            }

            CredentialVerifier supportingVerifier = resolveVerifier(authSession, credential.getId());
            JsonNode supportingClaims =
                    supportingVerifier.verifyCredential(context, authContext, authRequirements, credential, token);

            applyBindingRules(
                    context, credential, supportingVerifier, supportingClaims, primaryVerifier, primaryClaims, user);
        }
    }

    void applyBindingRules(
            AuthenticationFlowContext context,
            CredentialRequirement credential,
            CredentialVerifier supportingVerifier,
            JsonNode supportingClaims,
            CredentialVerifier primaryVerifier,
            JsonNode primaryClaims,
            UserModel user)
            throws VerificationException {

        for (BindingRule rule : credential.getBinding()) {
            String supportingValue = supportingVerifier.readClaim(supportingClaims, rule.getCredentialClaim());
            String expectedValue =
                    switch (rule.getType()) {
                        case BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM -> {
                            if (primaryVerifier == null || primaryClaims == null) {
                                throw new VerificationException(String.format(
                                        "Binding rule '%s' is not applicable to the primary credential '%s'",
                                        rule.getType(), credential.getId()));
                            }
                            yield primaryVerifier.readClaim(primaryClaims, rule.getPrimaryCredentialClaim());
                        }
                        case BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE ->
                            readUserAttribute(user, rule.getUserAttribute());
                        default ->
                            throw new IllegalStateException(
                                    String.format("Unsupported binding rule type: %s", rule.getType()));
                    };

            if (!resolveComparator(context.getSession(), rule).matches(supportingValue, expectedValue)) {
                throw new VerificationException(String.format(
                        "%s credential '%s' failed binding rule '%s'",
                        credential.isPrimary() ? "Primary" : "Supporting", credential.getId(), rule.getType()));
            }
        }
    }

    private BindingValueComparator resolveComparator(KeycloakSession session, BindingRule rule)
            throws VerificationException {
        String comparatorId = StringUtil.isBlank(rule.getComparator())
                ? ExactBindingValueComparatorFactory.PROVIDER_ID
                : rule.getComparator();
        BindingValueComparator comparator = session.getProvider(BindingValueComparator.class, comparatorId);
        if (comparator == null) {
            throw new VerificationException(String.format("Unknown binding comparator '%s'", comparatorId));
        }
        return comparator;
    }

    private static String readUserAttribute(UserModel user, String userAttribute) {
        return switch (userAttribute) {
            case "given_name", "firstName" -> user.getFirstName();
            case "family_name", "lastName" -> user.getLastName();
            case "username", "preferred_username" -> user.getUsername();
            default -> user.getFirstAttribute(userAttribute);
        };
    }

    private AuthorizationContext getAuthorizationContext(AuthenticationSessionModel authSession) {
        return new AuthenticationSessionStore(authSession).getAuthorizationContext();
    }

    private AuthenticationProfile getAuthenticationProfile(AuthenticationFlowContext context) {
        OID4VPProfileConfig profileConfig = new OID4VPProfileConfig(context.getAuthenticatorConfig());
        AuthorizationContext authContext = getAuthorizationContext(context.getAuthenticationSession());
        return profileConfig.getProfile(authContext.getProfileId());
    }

    private Map<String, String> getPresentedTokens(AuthenticationSessionModel authSession) {
        String tokensJson = authSession.getAuthNote(PRESENTED_TOKENS_KEY);
        if (StringUtil.isBlank(tokensJson)) {
            return Map.of();
        }

        try {
            return JsonSerialization.readValue(tokensJson, new TypeReference<>() {});
        } catch (IOException e) {
            throw new IllegalStateException("Invalid OID4VP presented credentials auth note", e);
        }
    }

    private static Map<String, String> supportingPresentedTokens(
            Map<String, String> presentedTokens, String primaryCredentialId) {
        return presentedTokens.entrySet().stream()
                .filter(e -> !primaryCredentialId.equals(e.getKey()))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private UserModel recoverAuthenticatingUser(
            AuthenticationFlowContext context,
            AuthorizationContext authContext,
            CredentialRequirement primaryCredential,
            CredentialVerifier verifier,
            JsonNode primaryClaims) {
        logger.info("Recovering authenticating user");

        if (primaryCredential.isSessionIdentity()) {
            String subjectUserId = authContext.getSubjectUserId();
            if (StringUtil.isBlank(subjectUserId)) {
                failRejectingPresentedCredential(context, "Missing session-bound subject user");
                return null;
            }
            return recoverPresentationSubject(context, subjectUserId);
        }

        String subject = verifier.readClaim(primaryClaims, JsonWebToken.SUBJECT);
        if (StringUtil.isBlank(subject)) {
            logger.warn("Presented credential is missing subject claim");
        } else {
            logger.debugf("Presented subject: %s", subject);
        }

        String presentedUsername = verifier.readClaim(primaryClaims, OAuth2Constants.USERNAME);
        if (StringUtil.isBlank(presentedUsername)) {
            logger.warn("Presented credential is missing required username claim");
            failRejectingPresentedCredential(context, "Missing username claim");
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
            failRejectingPresentedCredential(context, "Username mismatch");
            return null;
        }

        return user;
    }

    private UserModel recoverPresentationSubject(AuthenticationFlowContext context, String subjectUserId) {
        UserModel user = context.getSession().users().getUserById(context.getRealm(), subjectUserId);
        if (user == null) {
            logger.warnf("Credential offer subject '%s' did not resolve to a user", subjectUserId);
            failDenyingAuthenticatingUser(context);
            return null;
        }
        logger.debugf("Resolved presentation-during-issuance subject user id: %s", user.getId());
        return user;
    }

    private static String correlationId(AuthenticationFlowContext context) {
        return ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
    }

    private void failRejectingPresentedCredential(AuthenticationFlowContext context, String reason) {
        failRejectingPresentedCredential(context, reason, null);
    }

    private void failRejectingPresentedCredential(AuthenticationFlowContext context, String reason, Throwable cause) {
        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        if (cause != null) {
            logger.errorf(cause, "Presented OID4VP credential rejected (authSession = %s): %s", correlationId, reason);
        } else {
            logger.errorf("Presented OID4VP credential rejected (authSession = %s): %s", correlationId, reason);
        }

        String description = String.format("Invalid OID4VP credential presentation (%s)", reason);
        var errorRep = new OAuth2ErrorRepresentation(Errors.INVALID_USER_CREDENTIALS, description);

        context.failure(
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingAuthenticatingUser(AuthenticationFlowContext context) {
        logger.info("Presented OID4VP credential will be rejected for associated user is unknown");

        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(context.getAuthenticationSession());
        logger.errorf("User with presented OID4VP credential is unknown (authSession = %s)", correlationId);

        String description = "User with presented OID4VP credential is unknown";

        var errorRep = new OAuth2ErrorRepresentation(Errors.USER_NOT_FOUND, description);

        context.failure(
                AuthenticationFlowError.UNKNOWN_USER,
                Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                        .type(MediaType.APPLICATION_JSON_TYPE)
                        .entity(errorRep)
                        .build());
    }

    private void failDenyingDisabledUser(AuthenticationFlowContext context) {
        var errorRep = new OAuth2ErrorRepresentation(
                Errors.USER_DISABLED, "User with presented OID4VP credential is disabled");

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
