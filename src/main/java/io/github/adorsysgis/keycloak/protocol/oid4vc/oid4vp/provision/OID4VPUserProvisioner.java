package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.OID4VPUserAttributeMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPImportConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.broker.provider.IdentityProviderMapperSyncModeDelegate;
import org.keycloak.common.VerificationException;
import org.keycloak.events.Details;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.userprofile.ValidationException;
import org.keycloak.utils.StringUtil;

/**
 * Prompt-free provisioning of externally issued OpenID4VP identities, mirroring Keycloak's first
 * broker login: federated-link-first resolution, mapper staging, collision checks, creation, link,
 * import hooks, and a registration audit event.
 *
 * <p>Nothing here verifies credentials. Callers pass fully verified results; this class only
 * resolves, validates, creates, links, and synchronizes users.
 */
public class OID4VPUserProvisioner {

    private static final Logger logger = Logger.getLogger(OID4VPUserProvisioner.class);

    /**
     * Everything the provisioner needs for one external identity. The presentation must be fully
     * verified, including supporting credentials, claim-to-primary bindings, and transaction data.
     */
    public record Request(
            KeycloakSession session,
            RealmModel realm,
            OID4VPAuthenticator authenticator,
            OID4VPAuthenticator.Context context,
            OID4VPImportConfig importConfig,
            CredentialRequirement primaryRequirement,
            JsonNode primaryClaims,
            Map<CredentialRequirement, JsonNode> supporting,
            EventBuilder event) {}

    /**
     * Looks up the federated link for an external identity.
     *
     * @return the linked user, or {@code null} when the identity is unknown
     */
    public UserModel findLinkedUser(KeycloakSession session, RealmModel realm, String alias, String externalId) {
        return session.users()
                .getUserByFederatedIdentity(realm, new FederatedIdentityModel(alias, externalId, externalId));
    }

    /**
     * Creates, links, and returns the user for an unknown external identity.
     *
     * @throws UserProvisioningException for every expected refusal; nothing is written then
     * @throws IllegalStateException after the first write failed, with the transaction marked
     *     rollback-only, so no partial user, link, or attribute survives
     */
    public UserModel provisionNewUser(Request request, String externalId) throws UserProvisioningException {
        KeycloakSession session = request.session();
        RealmModel realm = request.realm();

        IdentityProviderModel idpConfig = resolveProvider(request);
        OID4VPImportIdentityProvider provider = new OID4VPImportIdentityProvider(session, idpConfig);
        String alias = idpConfig.getAlias();
        // The mapper stream is one-shot; materialize it once and share it between staging and hooks.
        List<IdentityProviderMapperModel> mappers =
                session.identityProviders().getMappersByAliasStream(alias).toList();

        // Fail closed when a concurrent import linked the identity while staging ran.
        if (findLinkedUser(session, realm, alias, externalId) != null) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.DUPLICATE,
                    "External identity was linked concurrently; retry the login");
        }

        BrokeredIdentityContext brokerContext = stageBrokeredContext(request, provider, idpConfig, externalId, mappers);

        evaluateStagedBindings(
                request, attribute -> OID4VPAuthenticator.readStagedUserAttribute(brokerContext, attribute));

        String proposedUsername = effectiveUsername(realm, brokerContext);
        // Collisions fail fast with the broker's duplicate semantics before profile validation:
        // a colliding account is a different problem than malformed staged data.
        checkCollisions(session, realm, proposedUsername, brokerContext.getEmail());

        UserProfile profile = validateStagedProfile(request, brokerContext, proposedUsername);
        Map<String, List<String>> persistedAttributes =
                new LinkedHashMap<>(profile.getAttributes().getWritable());
        // The profile's user factory creates the username even when it is not editable.
        String finalUsername = profile.getAttributes().getFirst(UserModel.USERNAME);
        if (finalUsername == null) {
            finalUsername = profile.getAttributes().getFirst(UserModel.EMAIL);
        }
        putIfPresent(persistedAttributes, UserModel.USERNAME, finalUsername);
        evaluateStagedBindings(request, attribute -> readProfileAttribute(persistedAttributes, attribute));
        checkCollisions(session, realm, finalUsername, readProfileAttribute(persistedAttributes, UserModel.EMAIL));

        // Recheck the link immediately before the first write.
        UserModel raced = findLinkedUser(session, realm, alias, externalId);
        if (raced != null) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.DUPLICATE,
                    "External identity was linked concurrently; retry the login");
        }

        UserModel user;
        try {
            user = profile.create();
        } catch (ModelDuplicateException e) {
            // Profile creation also persists attributes: a duplicate may occur after addUser.
            markRollbackOnly(session);
            UserModel concurrent = findLinkedUser(session, realm, alias, externalId);
            if (concurrent != null) {
                throw new UserProvisioningException(
                        UserProvisioningException.Reason.DUPLICATE,
                        "External identity was linked concurrently; retry the login",
                        e);
            }
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.DUPLICATE,
                    "An account with username '" + finalUsername + "' already exists",
                    e);
        } catch (RuntimeException e) {
            markRollbackOnly(session);
            throw new IllegalStateException("User import failed during the first write; transaction rolled back", e);
        }
        try {
            user.setEnabled(true);
            if (Boolean.TRUE.equals(idpConfig.isTrustEmail()) && user.getEmail() != null) {
                user.setEmailVerified(true);
            }

            session.users()
                    .addFederatedIdentity(
                            realm, user, new FederatedIdentityModel(alias, externalId, finalUsername, null));

            provider.importNewUser(session, realm, user, brokerContext);
            for (IdentityProviderMapperModel mapperModel : mappers) {
                IdentityProviderMapper mapper = mapper(session, mapperModel);
                mapper.importNewUser(session, realm, user, mapperModel, brokerContext);
            }
            provider.updateBrokeredUser(session, realm, user, brokerContext);
            emitRegistrationEvent(request.event(), alias, user);
        } catch (RuntimeException e) {
            // No orphan user, link, or attribute may survive a post-write failure. Escaping (rather
            // than setting a normal flow failure) guarantees the partial work never commits.
            markRollbackOnly(session);
            throw new IllegalStateException("User import failed after the first write; transaction rolled back", e);
        }

        return user;
    }

    /**
     * Verifies every credential-to-user-attribute binding and only then synchronizes a previously
     * linked user. Keeping verification and mutation behind this single public operation prevents
     * callers from accidentally updating the user before its bindings pass.
     *
     * <p>Synchronization mirrors the broker: basic attributes heal only in {@code FORCE} sync
     * mode, and mapper updates honor each mapper's effective sync mode (so {@code IMPORT} keeps
     * imported values untouched).
     */
    public void verifyAndSynchronizeExistingUser(
            Request request, IdentityProviderModel idpConfig, String externalId, UserModel user)
            throws UserProvisioningException {
        evaluateExistingUserBindings(request, user);
        try {
            synchronizeExistingUser(request, idpConfig, externalId, user);
        } catch (RuntimeException e) {
            markRollbackOnly(request.session());
            throw new IllegalStateException("Linked-user synchronization failed; transaction rolled back", e);
        }
    }

    private void synchronizeExistingUser(
            Request request, IdentityProviderModel idpConfig, String externalId, UserModel user) {
        KeycloakSession session = request.session();
        RealmModel realm = request.realm();
        OID4VPImportIdentityProvider provider = new OID4VPImportIdentityProvider(session, idpConfig);
        // The mapper stream is one-shot; materialize it once and share it between staging and hooks.
        List<IdentityProviderMapperModel> mappers = session.identityProviders()
                .getMappersByAliasStream(idpConfig.getAlias())
                .toList();
        BrokeredIdentityContext brokerContext = rebuildBrokeredContext(
                session, realm, provider, idpConfig, externalId, request.primaryClaims(), user, mappers);
        String previousEmail = user.getEmail();

        if (IdentityProviderSyncMode.FORCE.equals(idpConfig.getSyncMode())) {
            setIfDifferent(user.getFirstName(), brokerContext.getFirstName(), user::setFirstName);
            setIfDifferent(user.getLastName(), brokerContext.getLastName(), user::setLastName);
            if (brokerContext.getUsername() != null
                    && !brokerContext.getUsername().equals(user.getUsername())) {
                user.setUsername(brokerContext.getUsername());
            }
        }

        provider.updateBrokeredUser(session, realm, user, brokerContext);
        for (IdentityProviderMapperModel mapperModel : mappers) {
            IdentityProviderMapper mapper = mapper(session, mapperModel);
            IdentityProviderMapperSyncModeDelegate.delegateUpdateBrokeredUser(
                    session, realm, user, mapperModel, brokerContext, mapper);
        }
        // This authenticator does not run a broker authentication session. Keycloak's inherited
        // email updater therefore does nothing; reconcile verification after effective mapper
        // updates so a new address never inherits verification from the previous one.
        String updatedEmail = user.getEmail();
        if (previousEmail == null
                ? updatedEmail != null
                : updatedEmail == null || !previousEmail.equalsIgnoreCase(updatedEmail)) {
            user.setEmailVerified(updatedEmail != null && Boolean.TRUE.equals(idpConfig.isTrustEmail()));
        }
    }

    private void markRollbackOnly(KeycloakSession session) {
        try {
            session.getTransactionManager().setRollbackOnly();
        } catch (RuntimeException rollbackError) {
            logger.warnf(rollbackError, "Failed to mark the user-import transaction rollback-only");
        }
    }

    private void evaluateExistingUserBindings(Request request, UserModel user) throws UserProvisioningException {
        OID4VPAuthenticator authenticator = request.authenticator();
        OID4VPAuthenticator.Context context = request.context();

        try {
            authenticator.applyUserAttributeBindings(
                    context, request.primaryRequirement(), request.primaryClaims(), user);
        } catch (VerificationException | IllegalStateException e) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.BINDING,
                    "Primary credential binding checks failed: " + e.getMessage(),
                    e);
        }

        try {
            for (Map.Entry<CredentialRequirement, JsonNode> supporting :
                    request.supporting().entrySet()) {
                authenticator.applyUserAttributeBindings(context, supporting.getKey(), supporting.getValue(), user);
            }
        } catch (VerificationException | IllegalStateException e) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.BINDING,
                    "Supporting credential verification failed: " + e.getMessage(),
                    e);
        }
    }

    private IdentityProviderModel resolveProvider(Request request) throws UserProvisioningException {
        try {
            return request.importConfig().resolveImportIdentityProvider(request.session(), request.realm());
        } catch (IllegalStateException e) {
            throw new UserProvisioningException(UserProvisioningException.Reason.NOT_CONFIGURED, e.getMessage(), e);
        }
    }

    private BrokeredIdentityContext stageBrokeredContext(
            Request request,
            OID4VPImportIdentityProvider provider,
            IdentityProviderModel idpConfig,
            String externalId,
            List<IdentityProviderMapperModel> mappers) {
        CredentialVerifier verifier = request.context()
                .credentialVerifiers()
                .get(request.primaryRequirement().getId());
        String initialUsername = deriveUsername(verifier.readClaim(
                request.primaryClaims(), request.primaryRequirement().getSubjectClaim()));

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext(externalId, idpConfig);
        brokerContext.setIdp(provider);
        brokerContext.setUsername(initialUsername);
        brokerContext.setModelUsername(initialUsername);
        brokerContext.setBrokerUserId(idpConfig.getAlias() + "." + externalId);
        brokerContext.getContextData().put(OID4VPImportIdentityProvider.CREDENTIAL_CLAIMS, request.primaryClaims());

        stageSupportedMappers(request.session(), request.realm(), mappers, brokerContext);
        return brokerContext;
    }

    private BrokeredIdentityContext rebuildBrokeredContext(
            KeycloakSession session,
            RealmModel realm,
            OID4VPImportIdentityProvider provider,
            IdentityProviderModel idpConfig,
            String externalId,
            JsonNode primaryClaims,
            UserModel user,
            List<IdentityProviderMapperModel> mappers) {
        String username = user.getUsername();

        BrokeredIdentityContext brokerContext = new BrokeredIdentityContext(externalId, idpConfig);
        brokerContext.setIdp(provider);
        brokerContext.setUsername(username);
        brokerContext.setModelUsername(username);
        brokerContext.setBrokerUserId(idpConfig.getAlias() + "." + brokerContext.getId());
        brokerContext.getContextData().put(OID4VPImportIdentityProvider.CREDENTIAL_CLAIMS, primaryClaims);

        stageSupportedMappers(session, realm, mappers, brokerContext);
        return brokerContext;
    }

    /**
     * Runs the supported, context-only mapper to stage values on the context. Third-party mappers
     * stay out of staging; their import and update hooks still run once a user exists.
     */
    private void stageSupportedMappers(
            KeycloakSession session,
            RealmModel realm,
            List<IdentityProviderMapperModel> mappers,
            BrokeredIdentityContext brokerContext) {
        for (IdentityProviderMapperModel mapperModel : mappers) {
            IdentityProviderMapper mapper = mapper(session, mapperModel);
            if (mapper instanceof OID4VPUserAttributeMapper supported) {
                try {
                    supported.preprocessFederatedIdentity(session, realm, mapperModel, brokerContext);
                } catch (RuntimeException e) {
                    logger.warnf(
                            e,
                            "User import mapper '%s' failed during staging; import cannot continue",
                            mapperModel.getName());
                    throw e;
                }
            } else {
                logger.debugf(
                        "Skipping mapper '%s' during import staging; only the supported attribute mapper stages values",
                        mapperModel.getName());
            }
        }
    }

    private void evaluateStagedBindings(Request request, Function<String, String> attributes)
            throws UserProvisioningException {
        OID4VPAuthenticator authenticator = request.authenticator();
        OID4VPAuthenticator.Context context = request.context();

        try {
            authenticator.applyUserAttributeBindings(
                    context, request.primaryRequirement(), request.primaryClaims(), attributes);
            for (Map.Entry<CredentialRequirement, JsonNode> supporting :
                    request.supporting().entrySet()) {
                authenticator.applyUserAttributeBindings(
                        context, supporting.getKey(), supporting.getValue(), attributes);
            }
        } catch (VerificationException | IllegalStateException e) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.BINDING,
                    "Staged user data violates a credential binding rule: " + e.getMessage(),
                    e);
        }
    }

    private UserProfile validateStagedProfile(Request request, BrokeredIdentityContext brokerContext, String username)
            throws UserProvisioningException {
        Map<String, List<String>> attributes = new LinkedHashMap<>();
        putIfPresent(attributes, UserModel.USERNAME, username);
        putIfPresent(attributes, UserModel.EMAIL, brokerContext.getEmail());
        putIfPresent(attributes, UserModel.FIRST_NAME, brokerContext.getFirstName());
        putIfPresent(attributes, UserModel.LAST_NAME, brokerContext.getLastName());
        for (Map.Entry<String, List<String>> staged :
                brokerContext.getAttributes().entrySet()) {
            if (!attributes.containsKey(staged.getKey())
                    && staged.getValue() != null
                    && !staged.getValue().isEmpty()) {
                attributes.put(staged.getKey(), new ArrayList<>(staged.getValue()));
            }
        }

        try {
            UserProfile profile = request.session()
                    .getProvider(UserProfileProvider.class)
                    .create(UserProfileContext.REGISTRATION, attributes);
            profile.validate();
            return profile;
        } catch (ValidationException e) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.INVALID_PROFILE,
                    "Staged user data violates the realm user profile: " + e.getMessage(),
                    e);
        }
    }

    private void checkCollisions(KeycloakSession session, RealmModel realm, String username, String email)
            throws UserProvisioningException {
        if (email != null && !realm.isDuplicateEmailsAllowed()) {
            UserModel existing = session.users().getUserByEmail(realm, email);
            if (existing != null) {
                throw new UserProvisioningException(
                        UserProvisioningException.Reason.DUPLICATE,
                        "An account with email '" + email + "' already exists");
            }
            if (realm.isLoginWithEmailAllowed() && session.users().getUserByUsername(realm, email) != null) {
                throw new UserProvisioningException(
                        UserProvisioningException.Reason.DUPLICATE,
                        "An account with username '" + email + "' already exists");
            }
        }
        if (session.users().getUserByUsername(realm, username) != null) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.DUPLICATE,
                    "An account with username '" + username + "' already exists");
        }
        if (realm.isLoginWithEmailAllowed()
                && username != null
                && username.indexOf('@') > 0
                && session.users().getUserByEmail(realm, username) != null) {
            throw new UserProvisioningException(
                    UserProvisioningException.Reason.DUPLICATE,
                    "An account with email '" + username + "' already exists");
        }
    }

    /** Reads the first nonblank value Keycloak will persist, using the binding aliases. */
    private static String readProfileAttribute(Map<String, List<String>> attributes, String name) {
        String key =
                switch (name) {
                    case "given_name", "firstName" -> UserModel.FIRST_NAME;
                    case "family_name", "lastName" -> UserModel.LAST_NAME;
                    case "preferred_username", "username" -> UserModel.USERNAME;
                    default -> name;
                };
        List<String> values = attributes.get(key);
        return values == null
                ? null
                : values.stream().filter(StringUtil::isNotBlank).findFirst().orElse(null);
    }

    private void emitRegistrationEvent(EventBuilder event, String alias, UserModel user) {
        if (event == null) {
            return;
        }
        EventBuilder registration = event.clone();
        registration
                .event(EventType.REGISTER)
                .detail(Details.IDENTITY_PROVIDER, alias)
                .detail(Details.REGISTER_METHOD, "oid4vp")
                .user(user);
        if (user.getEmail() != null) {
            registration.detail(Details.EMAIL, user.getEmail());
        }
        registration.success();
    }

    private IdentityProviderMapper mapper(KeycloakSession session, IdentityProviderMapperModel mapperModel) {
        try {
            IdentityProviderMapper mapper = (IdentityProviderMapper) session.getKeycloakSessionFactory()
                    .getProviderFactory(IdentityProviderMapper.class, mapperModel.getIdentityProviderMapper());
            if (mapper == null) {
                throw new IllegalStateException(String.format(
                        "No user import mapper registered for id '%s' (mapper '%s')",
                        mapperModel.getIdentityProviderMapper(), mapperModel.getName()));
            }
            return mapper;
        } catch (RuntimeException e) {
            throw new IllegalStateException("Cannot resolve user import mapper '" + mapperModel.getName() + "'", e);
        }
    }

    private String effectiveUsername(RealmModel realm, BrokeredIdentityContext brokerContext) {
        if (realm.isRegistrationEmailAsUsername()) {
            return brokerContext.getEmail() != null ? brokerContext.getEmail() : brokerContext.getModelUsername();
        }
        return brokerContext.getModelUsername();
    }

    static String deriveUsername(String subject) {
        String base = subject == null ? "" : subject;
        String sanitised =
                base.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9._@-]+", "-").replaceAll("-{2,}", "-");
        sanitised = sanitised.replaceAll("^-+|-+$", "");
        if (!sanitised.isEmpty()) {
            return sanitised;
        }
        return "oid4vp-unknown-user";
    }

    private static void putIfPresent(Map<String, List<String>> attributes, String key, String value) {
        if (value != null) {
            attributes.put(key, List.of(value));
        }
    }

    private static void setIfDifferent(String current, String staged, Consumer<String> setter) {
        String currentValue = current == null ? "" : current;
        if (staged != null && !staged.equals(currentValue)) {
            setter.accept(staged);
        }
    }
}
