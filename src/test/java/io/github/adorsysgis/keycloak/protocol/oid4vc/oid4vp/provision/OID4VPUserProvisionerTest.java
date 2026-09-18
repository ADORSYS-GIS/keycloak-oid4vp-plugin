package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialIdentity;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialOrigin;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.AbstractOID4VPClaimMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.OID4VPUserAttributeMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.OID4VPImportConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRole;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderMapperSyncMode;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.userprofile.UserProfile;
import org.keycloak.userprofile.UserProfileContext;
import org.keycloak.userprofile.UserProfileProvider;
import org.keycloak.util.JsonSerialization;

/**
 * Covers the prompt-free provisioner: link-first resolution, creation with staged mapper values,
 * collision refusal without writes, and rollback after post-write failures.
 */
class OID4VPUserProvisionerTest {

    private static final String ALIAS = "oid4vp-import";
    private static final String EXTERNAL_ID = CredentialIdentity.externalId("https://issuer.example.com", "sub-1");

    private final OID4VPUserProvisioner provisioner = new OID4VPUserProvisioner();
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserProvider users = mock(UserProvider.class);
    private final UserProfileProvider profiles = mock(UserProfileProvider.class);
    private final UserProfile profile = mock(UserProfile.class);

    @BeforeEach
    void setUp() {
        when(session.users()).thenReturn(users);
        when(session.getProvider(UserProfileProvider.class)).thenReturn(profiles);
        when(profiles.create(any(UserProfileContext.class), any(Map.class))).thenReturn(profile);
        when(realm.getName()).thenReturn("test");
        when(realm.getIdentityProviderByAlias(ALIAS)).thenReturn(idpModel());
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of());
    }

    @Test
    void createsLinksAndReturnsUnknownUser() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"sub\":\"sub-1\"}");
        OID4VPUserProvisioner.Request request = request(claims);
        UserModel created = mock(UserModel.class);
        when(users.addUser(realm, "sub-1")).thenReturn(created);

        UserModel result = provisioner.provisionNewUser(request, EXTERNAL_ID);

        assertSame(created, result);
        verify(created).setEnabled(true);
        verify(users)
                .addFederatedIdentity(realm, created, new FederatedIdentityModel(ALIAS, EXTERNAL_ID, "sub-1", null));
    }

    @Test
    void refusesDuplicateUsernameWithoutWriting() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        when(users.getUserByUsername(realm, "sub-1")).thenReturn(mock(UserModel.class));

        UserProvisioningException e =
                assertThrows(UserProvisioningException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        assertEquals(UserProvisioningException.Reason.DUPLICATE, e.getReason());
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void refusesDuplicateEmailWithoutWriting() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"sub\":\"sub-1\",\"email\":\"taken@example.com\"}");
        stubEmailMapper();
        OID4VPUserProvisioner.Request request = request(claims);
        when(users.getUserByEmail(realm, "taken@example.com")).thenReturn(mock(UserModel.class));

        UserProvisioningException e = assertThrows(
                UserProvisioningException.class, () -> provisioner.provisionNewUser(request, "other-external-id"));

        assertEquals(UserProvisioningException.Reason.DUPLICATE, e.getReason());
        assertTrue(e.getMessage().contains("taken@example.com"));
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void stagedEmailReachesCreatedUser() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree(
                "{\"sub\":\"sub-1\",\"email\":\"ada@example.com\",\"given_name\":\"Ada\"}");
        stubEmailMapper();
        OID4VPUserProvisioner.Request request = request(claims);
        UserModel created = mock(UserModel.class);
        when(users.addUser(realm, "sub-1")).thenReturn(created);

        provisioner.provisionNewUser(request, EXTERNAL_ID);

        verify(created).setEmail("ada@example.com");
    }

    @Test
    void missingProviderFailsWithoutWriting() {
        when(realm.getIdentityProviderByAlias(ALIAS)).thenReturn(null);
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());

        UserProvisioningException e =
                assertThrows(UserProvisioningException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        assertEquals(UserProvisioningException.Reason.NOT_CONFIGURED, e.getReason());
        assertTrue(e.getMessage().contains(ALIAS));
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void postWriteFailureMarksRollbackOnly() throws Exception {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        UserModel created = mock(UserModel.class);
        when(users.addUser(realm, "sub-1")).thenReturn(created);
        doThrow(new RuntimeException("link store down"))
                .when(users)
                .addFederatedIdentity(any(RealmModel.class), any(UserModel.class), any(FederatedIdentityModel.class));
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        assertThrows(IllegalStateException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        verify(transactions).setRollbackOnly();
    }

    @Test
    void firstUserMutationFailureMarksRollbackOnly() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        UserModel created = mock(UserModel.class);
        when(users.addUser(realm, "sub-1")).thenReturn(created);
        doThrow(new RuntimeException("user store down")).when(created).setEnabled(true);
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        assertThrows(IllegalStateException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        verify(transactions).setRollbackOnly();
    }

    @Test
    void firstWriteFailureMarksRollbackOnly() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        when(users.addUser(realm, "sub-1")).thenThrow(new RuntimeException("user store down"));
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        assertThrows(IllegalStateException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        verify(transactions).setRollbackOnly();
    }

    @Test
    void concurrentLinkBeforeFirstWriteRequiresRetry() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        UserModel concurrentlyLinked = mock(UserModel.class);
        when(users.getUserByFederatedIdentity(any(RealmModel.class), any(FederatedIdentityModel.class)))
                .thenReturn(null, concurrentlyLinked);

        UserProvisioningException error =
                assertThrows(UserProvisioningException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        assertEquals(UserProvisioningException.Reason.DUPLICATE, error.getReason());
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void missingMapperFailsBeforeWriting() {
        IdentityProviderMapperModel mapperModel = mapperModel("missing-mapper");
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of(mapperModel));
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactory(IdentityProviderMapper.class, "missing-mapper"))
                .thenReturn(null);

        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());

        assertThrows(IllegalStateException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void mapperFailureAfterWritingMarksRollbackOnly() {
        IdentityProviderMapperModel mapperModel = mapperModel("failing-mapper");
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of(mapperModel));
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        IdentityProviderMapper mapper = mock(IdentityProviderMapper.class);
        when(sessionFactory.getProviderFactory(IdentityProviderMapper.class, "failing-mapper"))
                .thenReturn(mapper);

        UserModel created = mock(UserModel.class);
        when(users.addUser(realm, "sub-1")).thenReturn(created);
        doThrow(new RuntimeException("mapper failed"))
                .when(mapper)
                .importNewUser(
                        any(KeycloakSession.class),
                        any(RealmModel.class),
                        any(UserModel.class),
                        any(IdentityProviderMapperModel.class),
                        any(BrokeredIdentityContext.class));
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());

        assertThrows(IllegalStateException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));
        verify(transactions).setRollbackOnly();
    }

    @Test
    void concurrentLinkBeforeWriteRefusesWithDuplicate() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        when(users.getUserByFederatedIdentity(any(RealmModel.class), any(FederatedIdentityModel.class)))
                .thenReturn(null)
                .thenReturn(mock(UserModel.class));

        UserProvisioningException e =
                assertThrows(UserProvisioningException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        assertEquals(UserProvisioningException.Reason.DUPLICATE, e.getReason());
        assertTrue(e.getMessage().contains("concurrently"));
        verify(users, never()).addUser(any(RealmModel.class), anyString());
    }

    @Test
    void concurrentLinkDuringAddUserRefusesWithDuplicate() {
        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        when(users.addUser(realm, "sub-1")).thenThrow(new ModelDuplicateException("duplicate"));
        when(users.getUserByFederatedIdentity(any(RealmModel.class), any(FederatedIdentityModel.class)))
                .thenReturn(null)
                .thenReturn(null)
                .thenReturn(mock(UserModel.class));

        UserProvisioningException e =
                assertThrows(UserProvisioningException.class, () -> provisioner.provisionNewUser(request, EXTERNAL_ID));

        assertEquals(UserProvisioningException.Reason.DUPLICATE, e.getReason());
        assertTrue(e.getMessage().contains("concurrently"));
    }

    @Test
    void mapperFailureDuringLinkedUserSynchronizationMarksRollbackOnly() {
        IdentityProviderMapperModel mapperModel = mapperModel("failing-mapper");
        mapperModel.setSyncMode(IdentityProviderMapperSyncMode.FORCE);
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of(mapperModel));
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        IdentityProviderMapper mapper = mock(IdentityProviderMapper.class);
        when(mapper.supportsSyncMode(any())).thenReturn(true);
        when(sessionFactory.getProviderFactory(IdentityProviderMapper.class, "failing-mapper"))
                .thenReturn(mapper);

        UserModel linked = mock(UserModel.class);
        when(linked.getUsername()).thenReturn("sub-1");
        doThrow(new RuntimeException("sync mapper failed"))
                .when(mapper)
                .updateBrokeredUser(
                        any(KeycloakSession.class),
                        any(RealmModel.class),
                        any(UserModel.class),
                        any(IdentityProviderMapperModel.class),
                        any(BrokeredIdentityContext.class));
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        OID4VPUserProvisioner.Request request = request(JsonSerialization.mapper.createObjectNode());
        OID4VPImportIdentityProviderConfig idpConfig = new OID4VPImportIdentityProviderConfig(idpModel());

        assertThrows(
                IllegalStateException.class,
                () -> provisioner.verifyAndSynchronizeExistingUser(request, idpConfig, EXTERNAL_ID, linked));
        verify(transactions).setRollbackOnly();
    }

    @Test
    void findLinkedUserReturnsNullWhenUnknown() {
        when(users.getUserByFederatedIdentity(any(RealmModel.class), any(FederatedIdentityModel.class)))
                .thenReturn(null);

        assertNull(provisioner.findLinkedUser(session, realm, ALIAS, EXTERNAL_ID));
    }

    private void stubEmailMapper() {
        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setName("email-mapper");
        mapperModel.setIdentityProviderAlias(ALIAS);
        mapperModel.setIdentityProviderMapper(OID4VPUserAttributeMapper.PROVIDER_ID);
        mapperModel.setConfig(
                Map.of(AbstractOID4VPClaimMapper.CLAIM, "email", OID4VPUserAttributeMapper.USER_ATTRIBUTE, "email"));
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of(mapperModel));
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactory(eq(IdentityProviderMapper.class), anyString()))
                .thenReturn(new OID4VPUserAttributeMapper());
    }

    private IdentityProviderMapperModel mapperModel(String providerId) {
        IdentityProviderMapperModel mapperModel = new IdentityProviderMapperModel();
        mapperModel.setName(providerId);
        mapperModel.setIdentityProviderAlias(ALIAS);
        mapperModel.setIdentityProviderMapper(providerId);
        mapperModel.setConfig(new HashMap<>());
        return mapperModel;
    }

    private OID4VPUserProvisioner.Request request(JsonNode primaryClaims) {
        CredentialRequirement primary = new CredentialRequirement()
                .setId("pid")
                .setRole(CredentialRole.PRIMARY)
                .setSubjectClaim("sub")
                .setBinding(List.of());
        CredentialVerifier verifier = mock(CredentialVerifier.class);
        when(verifier.readClaim(primaryClaims, "sub")).thenReturn("sub-1");
        OID4VPAuthenticator authenticator = new OID4VPAuthenticator(Map.of());
        AuthenticationFlowContext flowContext = mock(AuthenticationFlowContext.class);
        when(flowContext.getSession()).thenReturn(session);
        OID4VPAuthenticator.Context context = new OID4VPAuthenticator.Context(
                "id", flowContext, null, null, null, null, Map.of(), Map.of("pid", verifier));
        AuthenticatorConfigModel authConfig = new AuthenticatorConfigModel();
        authConfig.setConfig(Map.of("importUnknownUsers", "true"));

        return new OID4VPUserProvisioner.Request(
                session,
                realm,
                authenticator,
                context,
                new OID4VPImportConfig(authConfig),
                primary,
                new CredentialIdentity(CredentialOrigin.EXTERNAL, "https://issuer.example.com", "sub-1"),
                primaryClaims,
                Map.of(),
                null);
    }

    private static IdentityProviderModel idpModel() {
        IdentityProviderModel model = new IdentityProviderModel();
        model.setAlias(ALIAS);
        model.setProviderId(OID4VPImportIdentityProviderFactory.PROVIDER_ID);
        model.setEnabled(true);
        return model;
    }
}
