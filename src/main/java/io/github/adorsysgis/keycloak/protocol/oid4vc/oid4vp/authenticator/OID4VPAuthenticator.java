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
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
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
    public void authenticate(AuthenticationFlowContext authFlowContext) {
        Context ctx = gatherContext(authFlowContext);
        logger.debugf("Authenticating with OID4VPAuthenticator (authSession = %s)", ctx.id());

        // Verify primary credential and recover authenticating user
        AuthenticatingUser authUser;
        try {
            authUser = verifyPrimaryCredential(ctx);
        } catch (VerificationException e) {
            String msg = "Primary credential verification failed";
            logger.errorf(e, "%s (authSession = %s)", msg, ctx.id());
            failRejectingPresentedCredential(ctx, msg);
            return;
        }

        // Verify supporting credentials while enforcing binding to authenticating user
        try {
            verifySupportingCredentials(ctx, authUser);
        } catch (VerificationException e) {
            String msg = "Supporting credential verification failed";
            logger.errorf(e, "%s (authSession = %s)", msg, ctx.id());
            failRejectingPresentedCredential(ctx, msg);
            return;
        }

        // Authentication successful: attach authenticated user to context
        UserModel user = authUser.userModel();
        authFlowContext.setUser(user);
        authFlowContext.success();
        logger.debugf("User '%s' successfully authenticated", user.getUsername());
    }

    /**
     * Builds the {@link Context} carried throughout the authentication run.
     */
    private Context gatherContext(AuthenticationFlowContext authFlowContext) {
        AuthRequirements authRequirements = new AuthRequirements(authFlowContext.getAuthenticatorConfig());
        AuthenticationSessionModel authSession = authFlowContext.getAuthenticationSession();
        AuthorizationContext authContext = new AuthenticationSessionStore(authSession).getAuthorizationContext();

        String realmId = authFlowContext.getRealm().getId();
        OID4VPProfileConfig profileConfig =
                OID4VPProfileConfig.resolve(realmId, authFlowContext.getAuthenticatorConfig());
        AuthenticationProfile authProfile = profileConfig.getProfile(authContext.getProfileId());

        Map<String, String> presentedTokens = getPresentedTokens(authSession);
        Map<String, CredentialVerifier> credentialVerifiers = resolveVerifiers(authContext);

        String correlationId = ErrorResponseSanitizer.correlationIdFromAuthSession(authSession);
        return new Context(
                correlationId,
                authFlowContext,
                authSession,
                authContext,
                authProfile,
                authRequirements,
                presentedTokens,
                credentialVerifiers);
    }

    private AuthenticatingUser verifyPrimaryCredential(Context ctx) throws VerificationException {
        CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);
        CredentialVerifier primaryVerifier = ctx.credentialVerifiers().get(primaryCredentialReq.getId());
        String primaryToken = ctx.presentedTokens().get(primaryCredentialReq.getId());

        // Run credential verification and capture claims
        JsonNode primaryClaims;
        try {
            primaryClaims = primaryVerifier.verifyCredential(ctx, primaryCredentialReq, primaryToken);
            TransactionDataSupport.requireCredentialIdInAllEntries(
                    ctx.authorizationContext().getRequestObject().getTransactionData(), primaryCredentialReq.getId());
            primaryVerifier.validateTransactionData(ctx, primaryToken);
        } catch (VerificationException | IllegalArgumentException | IllegalStateException e) {
            String msg = "Primary credential verification failed";
            failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
            throw new VerificationException(msg, e);
        }

        // Recover authenticating user from Keycloak
        UserModel user = recoverAuthenticatingUser(ctx, primaryClaims);
        if (user == null) {
            throw new VerificationException("Failure recovering authenticating user");
        }
        AuthenticatingUser authUser = new AuthenticatingUser(user, primaryClaims);

        // Primary-credential binding rules establish that the verified credential belongs to the
        // recovered Keycloak user. This is especially important for session-identity profiles, where
        // the user comes from the issuance session rather than from identity claims in the credential.
        try {
            applyBindingRules(ctx, authUser, primaryCredentialReq, primaryClaims);
        } catch (VerificationException | IllegalStateException e) {
            String msg = "Primary credential binding checks failed";
            failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
            throw new VerificationException(msg, e);
        }

        return authUser;
    }

    private void verifySupportingCredentials(Context ctx, AuthenticatingUser authUser) throws VerificationException {
        for (CredentialRequirement credential : ctx.authenticationProfile().getCredentials()) {
            if (credential.isPrimary()) {
                continue;
            }

            String token = ctx.presentedTokens().get(credential.getId());
            if (StringUtil.isBlank(token)) {
                continue;
            }

            try {
                CredentialVerifier supportingVerifier =
                        ctx.credentialVerifiers().get(credential.getId());
                JsonNode supportingClaims = supportingVerifier.verifyCredential(ctx, credential, token);
                applyBindingRules(ctx, authUser, credential, supportingClaims);
            } catch (VerificationException | IllegalStateException e) {
                String msg = "Supporting credential verification failed";
                failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
                throw new VerificationException(msg, e);
            }
        }
    }

    void applyBindingRules(
            Context ctx, AuthenticatingUser authUser, CredentialRequirement credentialReq, JsonNode claims)
            throws VerificationException {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();

        for (BindingRule rule : credentialReq.getBinding()) {
            CredentialVerifier verifier = ctx.credentialVerifiers().get(credentialReq.getId());
            String actualValue = verifier.readClaim(claims, rule.getCredentialClaim());

            String expectedValue =
                    switch (rule.getType()) {
                        case BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM -> {
                            if (credentialReq.isPrimary()) {
                                throw new VerificationException(String.format(
                                        "Binding rule '%s' is not applicable to the primary credential '%s'",
                                        rule.getType(), credentialReq.getId()));
                            }
                            CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);
                            CredentialVerifier primaryVerifier =
                                    ctx.credentialVerifiers().get(primaryCredentialReq.getId());
                            yield primaryVerifier.readClaim(authUser.primaryClaims(), rule.getPrimaryCredentialClaim());
                        }
                        case BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE ->
                            readUserAttribute(authUser.userModel(), rule.getUserAttribute());
                        default ->
                            throw new IllegalStateException(
                                    String.format("Unsupported binding rule type: %s", rule.getType()));
                    };

            String normalizedActual = actualValue != null ? actualValue.strip() : actualValue;
            String normalizedExpected = expectedValue != null ? expectedValue.strip() : expectedValue;
            if (rule.getCaseInsensitive() && normalizedActual != null && normalizedExpected != null) {
                normalizedActual = normalizedActual.toLowerCase(Locale.ROOT);
                normalizedExpected = normalizedExpected.toLowerCase(Locale.ROOT);
            }

            if (!resolveComparator(session, rule).matches(normalizedActual, normalizedExpected)) {
                throw new VerificationException(String.format(
                        "Credential '%s' failed binding rule '%s'", credentialReq.getId(), rule.getType()));
            }
        }
    }

    private UserModel recoverAuthenticatingUser(Context ctx, JsonNode primaryClaims) {
        logger.infof("Recovering authenticating user (authSession = %s)", ctx.id());
        CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);

        UserModel user = primaryCredentialReq.isSessionIdentity()
                ? recoverPresentationDuringIssuanceUser(ctx)
                : recoverUserFromClaims(ctx, primaryCredentialReq, primaryClaims);

        if (user == null) {
            return null;
        }

        logger.debugf("Recovered authenticating user has id '%s'", user.getId());

        if (!user.isEnabled()) {
            logger.debugf("Rejecting authentication for disabled user '%s'", user.getUsername());
            failDenyingDisabledUser(ctx);
            return null;
        }

        return user;
    }

    private CredentialRequirement getPresentedPrimaryCredential(Context ctx) {
        return ctx.authenticationProfile()
                .getPresentedPrimaryCredential(ctx.presentedTokens().keySet());
    }

    private UserModel recoverUserFromClaims(
            Context ctx, CredentialRequirement primaryCredentialReq, JsonNode primaryClaims) {
        CredentialVerifier verifier = ctx.credentialVerifiers().get(primaryCredentialReq.getId());
        String subject = verifier.readClaim(primaryClaims, primaryCredentialReq.getSubjectClaim());
        String username = verifier.readClaim(primaryClaims, primaryCredentialReq.getUsernameClaim());
        logger.debugf("Attempting user recovery with subject '%s' and username '%s'", subject, username);

        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();
        UserProvider userProvider = session.users();

        UserModel user = null;
        if (StringUtil.isNotBlank(subject)) {
            user = userProvider.getUserById(realm, subject);
        }

        if (user == null && StringUtil.isNotBlank(username)) {
            // TODO: Remove username-only fallback once SubjectID mapper is fixed and stable.
            logger.warn("Subject did not resolve to a user. Falling back to username lookup");
            user = userProvider.getUserByUsername(realm, username);
        }

        if (user == null) {
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(ctx);
            return null;
        }

        if (StringUtil.isNotBlank(username) && !username.equals(user.getUsername())) {
            logger.warnf(
                    "Username mismatch for subject '%s': credential='%s', user='%s'",
                    subject, username, user.getUsername());
            failRejectingPresentedCredential(ctx, "Username mismatch");
            return null;
        }

        return user;
    }

    private UserModel recoverPresentationDuringIssuanceUser(Context ctx) {
        String subjectUserId = ctx.authorizationContext().getSubjectUserId();
        if (StringUtil.isBlank(subjectUserId)) {
            failRejectingPresentedCredential(ctx, "Missing session-bound subject user");
            return null;
        }

        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();
        UserModel user = session.users().getUserById(realm, subjectUserId);

        if (user == null) {
            logger.warnf("Credential offer subject '%s' did not resolve to a user", subjectUserId);
            failDenyingAuthenticatingUser(ctx);
            return null;
        }

        logger.debugf("Resolved presentation-during-issuance subject user id: %s", user.getId());
        return user;
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

    Map<String, CredentialVerifier> resolveVerifiers(AuthorizationContext authContext) {
        DcqlQuery dcqlQuery = authContext.getRequestObject().getDcqlQuery();
        if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
            throw new IllegalStateException("No DCQL query found in authorization context");
        }

        Map<String, CredentialVerifier> verifiers = new LinkedHashMap<>();
        for (Credential credential : dcqlQuery.getCredentials()) {
            String credentialId = credential.getId();
            String format = credential.getFormat();
            CredentialVerifier verifier = handlers.get(format);
            if (verifier == null) {
                throw new IllegalStateException(String.format(
                        "No registered verifier supports format '%s' for credential '%s'", format, credentialId));
            }
            // Clone the template verifier so per-verification state (e.g. verification context held
            // between verifyCredential and validateTransactionData) is not shared or clobbered across
            // concurrent authentication sessions.
            verifiers.put(credentialId, verifier.copy());
        }

        return verifiers;
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

    private void failRejectingPresentedCredential(Context ctx, String reason) {
        failAuthentication(
                ctx,
                AuthenticationFlowError.INVALID_CREDENTIALS,
                Errors.INVALID_USER_CREDENTIALS,
                String.format("Invalid OID4VP credential presentation: %s", reason));
    }

    private void failDenyingAuthenticatingUser(Context ctx) {
        failAuthentication(
                ctx,
                AuthenticationFlowError.UNKNOWN_USER,
                Errors.USER_NOT_FOUND,
                "User with presented OID4VP credential is unknown");
    }

    private void failDenyingDisabledUser(Context ctx) {
        failAuthentication(
                ctx,
                AuthenticationFlowError.USER_DISABLED,
                Errors.USER_DISABLED,
                "User with presented OID4VP credential is disabled");
    }

    private void failAuthentication(
            Context ctx, AuthenticationFlowError flowError, String errorCode, String description) {
        if (ctx.authenticationFlowContext().getStatus() == FlowStatus.FAILED) {
            logger.debugf(
                    "A failure has already been set; skipping '%s' (errorCode=%s) to preserve the "
                            + "previous failure (authSession = %s)",
                    description, errorCode, ctx.id());
            return;
        }

        var errorRep = new OAuth2ErrorRepresentation(errorCode, description);
        ctx.authenticationFlowContext()
                .failure(
                        flowError,
                        Response.status(Response.Status.UNAUTHORIZED.getStatusCode())
                                .type(MediaType.APPLICATION_JSON_TYPE)
                                .entity(errorRep)
                                .build());
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // No form action is relevant for this authenticator
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

    public record Context(
            String id,
            AuthenticationFlowContext authenticationFlowContext,
            AuthenticationSessionModel authenticationSession,
            AuthorizationContext authorizationContext,
            AuthenticationProfile authenticationProfile,
            AuthRequirements authRequirements,
            Map<String, String> presentedTokens,
            Map<String, CredentialVerifier> credentialVerifiers) {

        public Context {
            presentedTokens = Collections.unmodifiableMap(presentedTokens);
            credentialVerifiers = Collections.unmodifiableMap(credentialVerifiers);
        }
    }

    record AuthenticatingUser(UserModel userModel, JsonNode primaryClaims) {}
}
