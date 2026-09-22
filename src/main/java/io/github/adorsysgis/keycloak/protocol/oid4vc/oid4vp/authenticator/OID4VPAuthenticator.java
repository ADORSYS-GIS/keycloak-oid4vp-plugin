package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.BindingValueComparator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding.ExactBindingValueComparatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPImportConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.BindingRule;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.OID4VPProfileConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision.OID4VPUserProvisioner;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision.UserProvisioningException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthenticationSessionStore;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ErrorResponseSanitizer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.FlowStatus;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.Urls;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Authenticator that authenticates users via OpenID4VP presentation of verifiable credentials.
 *
 * <p>Format-specific verification (signature, holder binding, claim requirements, revocation,
 * transaction data) is delegated to a registered {@link CredentialVerifier}. The complete
 * presentation is verified before the user is resolved, so no user is ever created from or linked
 * to an unverified credential. Binding rules are split by kind: claim-to-primary-claim rules need
 * no user, while claim-to-user-attribute rules evaluate against the resolved user — or, for not
 * yet existing users, against staged import attributes.
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

        // Verify the complete presentation before resolving or changing any user.
        VerifiedPresentation presentation;
        try {
            presentation = verifyPresentation(ctx);
        } catch (VerificationException e) {
            logger.errorf(e, "Presentation verification failed (authSession = %s)", ctx.id());
            return;
        }

        // Resolve the authenticating user. Linked-user synchronization is deliberately deferred
        // until every user-dependent binding has passed.
        RecoveredUser recoveredUser = recoverAuthenticatingUser(ctx, presentation);
        if (recoveredUser == null) {
            return;
        }
        UserModel user = recoveredUser.user();

        // A newly imported user already passed these checks against its staged attributes before
        // it was created. Existing users must pass them against their current Keycloak attributes.
        if (recoveredUser.requiresDirectUserBindingCheck()) {
            try {
                applyUserAttributeBindings(
                        ctx,
                        presentation.primaryRequirement(),
                        presentation.primaryCredential().claims(),
                        user);
            } catch (VerificationException | IllegalStateException e) {
                String msg = "Primary credential binding checks failed";
                logger.errorf(e, "%s (authSession = %s)", msg, ctx.id());
                failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
                return;
            }

            try {
                applySupportingUserAttributeBindings(ctx, user, presentation);
            } catch (VerificationException | IllegalStateException e) {
                String msg = "Supporting credential verification failed";
                logger.errorf(e, "%s (authSession = %s)", msg, ctx.id());
                failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
                return;
            }
        }

        // This is the first point at which an existing linked user may be changed.
        if (!recoveredUser.afterBindings().run()) {
            return;
        }

        // Authentication successful: attach authenticated user to context
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

    /**
     * Verifies the selected primary credential and every presented supporting credential, including
     * transaction data, without resolving or changing any user. Claim-to-primary-claim bindings are
     * validated here as well since they need no user; claim-to-user-attribute bindings run later
     * against the resolved user or staged import attributes.
     */
    private VerifiedPresentation verifyPresentation(Context ctx) throws VerificationException {
        CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);
        CredentialVerifier primaryVerifier = ctx.credentialVerifiers().get(primaryCredentialReq.getId());
        String primaryToken = ctx.presentedTokens().get(primaryCredentialReq.getId());

        // Run primary credential verification and capture claims
        VerifiedCredential primaryCredential;
        try {
            primaryCredential = primaryVerifier.verifyCredential(ctx, primaryCredentialReq, primaryToken);
            TransactionDataSupport.requireCredentialIdInAllEntries(
                    ctx.authorizationContext().getRequestObject().getTransactionData(), primaryCredentialReq.getId());
            primaryVerifier.validateTransactionData(ctx, primaryToken);
        } catch (VerificationException | IllegalArgumentException | IllegalStateException e) {
            String msg = "Primary credential verification failed";
            failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
            throw new VerificationException(msg, e);
        }

        try {
            applyPrimaryClaimBindings(
                    ctx, primaryCredential.claims(), primaryCredentialReq, primaryCredential.claims());
        } catch (VerificationException | IllegalStateException e) {
            String msg = "Primary credential binding checks failed";
            failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
            throw new VerificationException(msg, e);
        }

        Map<CredentialRequirement, VerifiedCredential> supporting = new LinkedHashMap<>();
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
                VerifiedCredential verified = supportingVerifier.verifyCredential(ctx, credential, token);
                applyPrimaryClaimBindings(ctx, primaryCredential.claims(), credential, verified.claims());
                supporting.put(credential, verified);
            } catch (VerificationException | IllegalStateException e) {
                String msg = "Supporting credential verification failed";
                failRejectingPresentedCredential(ctx, String.format("%s: %s", msg, e.getMessage()));
                throw new VerificationException(msg, e);
            }
        }

        return new VerifiedPresentation(primaryCredentialReq, primaryCredential, supporting);
    }

    private void applySupportingUserAttributeBindings(Context ctx, UserModel user, VerifiedPresentation presentation)
            throws VerificationException {
        for (Map.Entry<CredentialRequirement, VerifiedCredential> entry :
                presentation.supporting().entrySet()) {
            applyUserAttributeBindings(ctx, entry.getKey(), entry.getValue().claims(), user);
        }
    }

    void applyBindingRules(
            Context ctx, AuthenticatingUser authUser, CredentialRequirement credentialReq, JsonNode claims)
            throws VerificationException {
        applyPrimaryClaimBindings(ctx, authUser.primaryClaims(), credentialReq, claims);
        applyUserAttributeBindings(
                ctx, credentialReq, claims, attribute -> readUserAttribute(authUser.userModel(), attribute));
    }

    /**
     * Evaluates the claim-to-primary-claim bindings of one credential. Needs only verified claims,
     * so it runs during presentation verification, before any user is resolved.
     */
    public void applyPrimaryClaimBindings(
            Context ctx, JsonNode primaryClaims, CredentialRequirement credentialReq, JsonNode claims)
            throws VerificationException {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();

        for (BindingRule rule : credentialReq.getBinding()) {
            if (!BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM.equals(rule.getType())) {
                if (!BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE.equals(rule.getType())) {
                    throw new IllegalStateException(String.format("Unsupported binding rule type: %s", rule.getType()));
                }
                continue;
            }
            if (credentialReq.isPrimary()) {
                throw new VerificationException(String.format(
                        "Binding rule '%s' is not applicable to the primary credential '%s'",
                        rule.getType(), credentialReq.getId()));
            }
            CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);
            CredentialVerifier primaryVerifier = ctx.credentialVerifiers().get(primaryCredentialReq.getId());
            CredentialVerifier verifier = ctx.credentialVerifiers().get(credentialReq.getId());
            compareBindingValues(
                    session,
                    rule,
                    credentialReq,
                    verifier.readClaim(claims, rule.getCredentialClaim()),
                    primaryVerifier.readClaim(primaryClaims, rule.getPrimaryCredentialClaim()));
        }
    }

    /**
     * Evaluates the claim-to-user-attribute bindings of one credential against the resolved user.
     */
    public void applyUserAttributeBindings(
            Context ctx, CredentialRequirement credentialReq, JsonNode claims, UserModel user)
            throws VerificationException {
        applyUserAttributeBindings(ctx, credentialReq, claims, attribute -> readUserAttribute(user, attribute));
    }

    /**
     * Evaluates the claim-to-user-attribute bindings of one credential against staged import
     * attributes. Used for not yet existing users, whose attributes were staged on a brokered
     * context by the import mappers; see {@link #readStagedUserAttribute}.
     */
    public void applyUserAttributeBindings(
            Context ctx, CredentialRequirement credentialReq, JsonNode claims, Function<String, String> userValueLookup)
            throws VerificationException {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        CredentialVerifier verifier = ctx.credentialVerifiers().get(credentialReq.getId());

        for (BindingRule rule : credentialReq.getBinding()) {
            if (!BindingRule.CLAIM_EQUALS_USER_ATTRIBUTE.equals(rule.getType())) {
                if (!BindingRule.CLAIM_EQUALS_PRIMARY_CLAIM.equals(rule.getType())) {
                    throw new IllegalStateException(String.format("Unsupported binding rule type: %s", rule.getType()));
                }
                continue;
            }
            compareBindingValues(
                    session,
                    rule,
                    credentialReq,
                    verifier.readClaim(claims, rule.getCredentialClaim()),
                    userValueLookup.apply(rule.getUserAttribute()));
        }
    }

    private void compareBindingValues(
            KeycloakSession session,
            BindingRule rule,
            CredentialRequirement credentialReq,
            String actualValue,
            String expectedValue)
            throws VerificationException {
        String normalizedActual = actualValue != null ? actualValue.strip() : actualValue;
        String normalizedExpected = expectedValue != null ? expectedValue.strip() : expectedValue;
        if (rule.getCaseInsensitive() && normalizedActual != null && normalizedExpected != null) {
            normalizedActual = normalizedActual.toLowerCase(Locale.ROOT);
            normalizedExpected = normalizedExpected.toLowerCase(Locale.ROOT);
        }

        if (!resolveComparator(session, rule).matches(normalizedActual, normalizedExpected)) {
            throw new VerificationException(
                    String.format("Credential '%s' failed binding rule '%s'", credentialReq.getId(), rule.getType()));
        }
    }

    private RecoveredUser recoverAuthenticatingUser(Context ctx, VerifiedPresentation presentation) {
        logger.infof("Recovering authenticating user (authSession = %s)", ctx.id());
        CredentialRequirement primaryCredentialReq = getPresentedPrimaryCredential(ctx);

        RecoveredUser recovered = primaryCredentialReq.isSessionIdentity()
                ? withoutDeferredMutation(recoverPresentationDuringIssuanceUser(ctx))
                : recoverUserFromClaims(ctx, primaryCredentialReq, presentation);

        if (recovered == null) {
            return null;
        }
        UserModel user = recovered.user();

        logger.debugf("Recovered authenticating user has id '%s'", user.getId());

        if (!user.isEnabled()) {
            logger.debugf("Rejecting authentication for disabled user '%s'", user.getUsername());
            failDenyingDisabledUser(ctx);
            return null;
        }

        return recovered;
    }

    private CredentialRequirement getPresentedPrimaryCredential(Context ctx) {
        return ctx.authenticationProfile()
                .getPresentedPrimaryCredential(ctx.presentedTokens().keySet());
    }

    private RecoveredUser recoverUserFromClaims(
            Context ctx, CredentialRequirement primaryCredentialReq, VerifiedPresentation presentation) {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();
        VerifiedCredential primaryCredential = presentation.primaryCredential();

        if (isSameRealmCredential(session, realm, primaryCredential.identity())) {
            return withoutDeferredMutation(recoverLocalUser(ctx, primaryCredentialReq, primaryCredential));
        }
        return recoverExternalUser(ctx, primaryCredentialReq, presentation);
    }

    /**
     * Origin is established by the format verifier from the verified signing key, independently of
     * the trust policy. The issuer URL comparison is an additional namespace consistency check.
     */
    private boolean isSameRealmCredential(KeycloakSession session, RealmModel realm, CredentialIdentity identity) {
        if (identity == null || identity.origin() != CredentialOrigin.CURRENT_REALM) {
            return false;
        }
        String realmIssuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        return realmIssuer.equals(identity.issuer());
    }

    private UserModel recoverLocalUser(
            Context ctx, CredentialRequirement primaryCredentialReq, VerifiedCredential primaryCredential) {
        CredentialVerifier verifier = ctx.credentialVerifiers().get(primaryCredentialReq.getId());
        String subject = verifier.readClaim(primaryCredential.claims(), primaryCredentialReq.getSubjectClaim());
        logger.debugf("Attempting local user recovery with credential subject '%s'", subject);

        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();

        UserModel user = null;
        if (StringUtil.isNotBlank(subject)) {
            user = session.users().getUserById(realm, subject);
        }

        if (user == null) {
            // A deleted local user must never be recreated from an old credential.
            logger.debugf("Authentication passed but authenticating user is unknown");
            failDenyingAuthenticatingUser(ctx);
            return null;
        }

        return user;
    }

    /**
     * Resolves an externally issued identity through its federated link, importing the user when
     * unknown and enabled. An external subject is never looked up as a local user id, username,
     * or email.
     */
    private RecoveredUser recoverExternalUser(
            Context ctx, CredentialRequirement primaryCredentialReq, VerifiedPresentation presentation) {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();
        CredentialIdentity identity = presentation.primaryCredential().identity();

        if (identity == null) {
            logger.debugf("External credential exposes no stable identity; failing closed");
            failDenyingAuthenticatingUser(ctx);
            return null;
        }

        OID4VPImportConfig importConfig =
                new OID4VPImportConfig(ctx.authenticationFlowContext().getAuthenticatorConfig());
        String alias = importConfig.getImportIdentityProviderAlias();
        String externalId = CredentialIdentity.externalId(identity.issuer(), identity.subject());
        OID4VPUserProvisioner provisioner = new OID4VPUserProvisioner();

        Map<CredentialRequirement, JsonNode> supporting = new LinkedHashMap<>();
        for (Map.Entry<CredentialRequirement, VerifiedCredential> entry :
                presentation.supporting().entrySet()) {
            supporting.put(entry.getKey(), entry.getValue().claims());
        }
        OID4VPUserProvisioner.Request request = new OID4VPUserProvisioner.Request(
                session,
                realm,
                this,
                ctx,
                importConfig,
                primaryCredentialReq,
                presentation.primaryCredential().claims(),
                supporting,
                ctx.authenticationFlowContext().getEvent());

        UserModel linked = provisioner.findLinkedUser(session, realm, alias, externalId);
        if (linked != null) {
            if (!linked.isEnabled()) {
                return withoutDeferredMutation(linked);
            }
            return new RecoveredUser(
                    linked,
                    false,
                    () -> synchronizeLinkedUser(ctx, importConfig, provisioner, alias, externalId, request, linked));
        }

        if (!importConfig.shouldImportUnknownUsers()) {
            logger.debugf("Authentication passed but authenticating user is unknown; import disabled");
            failDenyingAuthenticatingUser(ctx);
            return null;
        }

        try {
            UserModel imported = provisioner.provisionNewUser(request, externalId);
            return new RecoveredUser(imported, false, () -> true);
        } catch (UserProvisioningException e) {
            failProvisioning(ctx, e);
            return null;
        }
    }

    private static RecoveredUser withoutDeferredMutation(UserModel user) {
        return user == null ? null : new RecoveredUser(user, true, () -> true);
    }

    private boolean synchronizeLinkedUser(
            Context ctx,
            OID4VPImportConfig importConfig,
            OID4VPUserProvisioner provisioner,
            String alias,
            String externalId,
            OID4VPUserProvisioner.Request request,
            UserModel linked) {
        KeycloakSession session = ctx.authenticationFlowContext().getSession();
        RealmModel realm = ctx.authenticationFlowContext().getRealm();
        OID4VPImportIdentityProviderConfig idpConfig;
        try {
            idpConfig = importConfig.resolveImportIdentityProvider(session, realm);
        } catch (IllegalStateException e) {
            // The link outlives its provider configuration: log in without synchronizing rather
            // than locking out a previously imported user.
            logger.warnf(
                    "Linked user '%s' resolves via alias '%s' but the import provider is unusable: %s."
                            + " Authenticating without claim synchronization.",
                    linked.getUsername(), alias, e.getMessage());
            return true;
        }
        try {
            provisioner.verifyAndSynchronizeExistingUser(request, idpConfig, externalId, linked);
        } catch (UserProvisioningException e) {
            failProvisioning(ctx, e);
            return false;
        }
        logger.debugf("Resolved externally linked user with id '%s'", linked.getId());
        return true;
    }

    private void failProvisioning(Context ctx, UserProvisioningException e) {
        switch (e.getReason()) {
            case NOT_CONFIGURED -> {
                logger.warnf("User import refused: %s", e.getMessage());
                failDenyingAuthenticatingUser(ctx);
            }
            case DUPLICATE ->
                failAuthentication(
                        ctx,
                        AuthenticationFlowError.INVALID_CREDENTIALS,
                        Errors.FEDERATED_IDENTITY_EXISTS,
                        "An account matching the presented identity already exists");
            case BINDING, INVALID_PROFILE -> failRejectingPresentedCredential(ctx, e.getMessage());
        }
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
            case "email" -> user.getEmail();
            default -> user.getFirstAttribute(userAttribute);
        };
    }

    /**
     * Reads a user attribute from staged import values, mirroring {@link #readUserAttribute}
     * naming: predefined names resolve to the staged basic properties, anything else to the first
     * staged custom value.
     */
    public static String readStagedUserAttribute(BrokeredIdentityContext staged, String userAttribute) {
        return switch (userAttribute) {
            case "given_name", "firstName" -> staged.getFirstName();
            case "family_name", "lastName" -> staged.getLastName();
            case "username", "preferred_username" -> staged.getModelUsername();
            case "email" -> staged.getEmail();
            default -> {
                List<String> values = staged.getAttributes().get(userAttribute);
                yield values == null || values.isEmpty() ? null : values.get(0);
            }
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

    /**
     * A resolved user plus work that is safe only after user-attribute bindings pass. New imports
     * do not require another direct binding check because those checks ran against staged data
     * before creation.
     */
    @FunctionalInterface
    private interface PostBindingAction {
        boolean run();
    }

    private record RecoveredUser(
            UserModel user, boolean requiresDirectUserBindingCheck, PostBindingAction afterBindings) {}

    /**
     * The fully verified presentation: the presented primary credential and every presented
     * supporting credential, collected before any user is resolved or changed.
     */
    record VerifiedPresentation(
            CredentialRequirement primaryRequirement,
            VerifiedCredential primaryCredential,
            Map<CredentialRequirement, VerifiedCredential> supporting) {}
}
