package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.provision;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.OID4VPImportIdentityProviderConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.AbstractOID4VPClaimMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.OID4VPUserAttributeMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProviderMapper;
import org.keycloak.common.VerificationException;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderMapperSyncMode;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.util.JsonSerialization;

/**
 * Covers linked-user synchronization: mapped attributes heal only in {@code FORCE} sync mode,
 * while {@code IMPORT} keeps imported values untouched.
 */
class OID4VPUserSynchronizationTest {

    private static final String ALIAS = "oid4vp-import";

    private final OID4VPUserProvisioner provisioner = new OID4VPUserProvisioner();
    private final KeycloakSession session = mock(KeycloakSession.class);
    private final RealmModel realm = mock(RealmModel.class);
    private final UserModel user = mock(UserModel.class);
    private final OID4VPAuthenticator authenticator = mock(OID4VPAuthenticator.class);
    private final OID4VPAuthenticator.Context context = mock(OID4VPAuthenticator.Context.class);
    private final CredentialRequirement primaryRequirement = mock(CredentialRequirement.class);

    @BeforeEach
    void setUp() {
        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.getProviderFactory(eq(IdentityProviderMapper.class), anyString()))
                .thenReturn(new OID4VPUserAttributeMapper());
        when(user.getUsername()).thenReturn("external-sub-1");
        when(user.getEmail()).thenReturn("old@example.com");
        when(user.getFirstName()).thenReturn("Old");
    }

    @Test
    void forceSyncModeHealsMappedAttributes() throws Exception {
        // IdP-level FORCE heals basic attributes; the mapper-level FORCE delegate applies mapped
        // values on top, so the first name write lands twice with the same value.
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS))
                .thenReturn(Stream.of(
                        mapper("email-mapper", "email", "email", IdentityProviderMapperSyncMode.FORCE),
                        mapper("first-name-mapper", "given_name", "firstName", IdentityProviderMapperSyncMode.FORCE)));
        JsonNode claims = JsonSerialization.mapper.readTree("{\"email\":\"new@example.com\",\"given_name\":\"New\"}");
        OID4VPImportIdentityProviderConfig config = providerConfig(IdentityProviderSyncMode.FORCE);

        provisioner.verifyAndSynchronizeExistingUser(request(claims), config, "external-id", user);

        var order = inOrder(authenticator, user);
        order.verify(authenticator).applyUserAttributeBindings(context, primaryRequirement, claims, user);
        order.verify(user).setEmail("new@example.com");
        verify(user).setEmail("new@example.com");
        verify(user, times(2)).setFirstName("New");
    }

    @Test
    void importSyncModeKeepsImportedAttributes() throws Exception {
        // Mapper-level IMPORT: changed claims leave the user untouched (no basics healing either,
        // since the IdP mode is IMPORT, not FORCE).
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS))
                .thenReturn(Stream.of(
                        mapper("email-mapper", "email", "email", IdentityProviderMapperSyncMode.IMPORT),
                        mapper("first-name-mapper", "given_name", "firstName", IdentityProviderMapperSyncMode.IMPORT)));
        JsonNode claims = JsonSerialization.mapper.readTree("{\"email\":\"new@example.com\",\"given_name\":\"New\"}");
        OID4VPImportIdentityProviderConfig config = providerConfig(IdentityProviderSyncMode.IMPORT);

        provisioner.verifyAndSynchronizeExistingUser(request(claims), config, "external-id", user);

        verify(user, never()).setEmail(anyString());
        verify(user, never()).setFirstName(anyString());
        assertEquals("old@example.com", user.getEmail());
    }

    @Test
    void unsetMapperSyncModeFallsBackToLegacyUpdate() throws Exception {
        // Without an explicit mode the mapper behaves as LEGACY and applies claim updates, exactly
        // like the broker. Administrators wanting IMPORT stability must configure it explicitly.
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS))
                .thenReturn(Stream.of(emailMapper(), firstNameMapper()));
        JsonNode claims = JsonSerialization.mapper.readTree("{\"email\":\"new@example.com\",\"given_name\":\"New\"}");
        OID4VPImportIdentityProviderConfig config = providerConfig(IdentityProviderSyncMode.IMPORT);

        provisioner.verifyAndSynchronizeExistingUser(request(claims), config, "external-id", user);

        verify(user).setEmail("new@example.com");
    }

    @Test
    void bindingFailurePreventsSynchronization() throws Exception {
        JsonNode claims = JsonSerialization.mapper.readTree("{\"email\":\"new@example.com\"}");
        OID4VPImportIdentityProviderConfig config = providerConfig(IdentityProviderSyncMode.FORCE);
        doThrow(new VerificationException("mismatch"))
                .when(authenticator)
                .applyUserAttributeBindings(context, primaryRequirement, claims, user);

        UserProvisioningException error = assertThrows(
                UserProvisioningException.class,
                () -> provisioner.verifyAndSynchronizeExistingUser(request(claims), config, "external-id", user));

        assertEquals(UserProvisioningException.Reason.BINDING, error.getReason());
        verify(realm, never()).getIdentityProviderMappersByAliasStream(ALIAS);
        verify(user, never()).setEmail(anyString());
        verify(user, never()).setFirstName(anyString());
    }

    @Test
    void mapperFailureAfterMutationMarksRollbackOnly() throws Exception {
        IdentityProviderMapperModel firstName =
                mapper("first-name-mapper", "given_name", "firstName", IdentityProviderMapperSyncMode.FORCE);
        IdentityProviderMapperModel failing =
                mapper("failing-mapper", "ignored", "ignored", IdentityProviderMapperSyncMode.FORCE);
        failing.setIdentityProviderMapper("failing-mapper");
        when(realm.getIdentityProviderMappersByAliasStream(ALIAS)).thenReturn(Stream.of(firstName, failing));

        IdentityProviderMapper failingMapper = mock(IdentityProviderMapper.class);
        when(session.getKeycloakSessionFactory().getProviderFactory(IdentityProviderMapper.class, "failing-mapper"))
                .thenReturn(failingMapper);
        doThrow(new RuntimeException("mapper failed"))
                .when(failingMapper)
                .updateBrokeredUser(eq(session), eq(realm), eq(user), eq(failing), any(BrokeredIdentityContext.class));
        KeycloakTransactionManager transactions = mock(KeycloakTransactionManager.class);
        when(session.getTransactionManager()).thenReturn(transactions);

        JsonNode claims = JsonSerialization.mapper.readTree("{\"given_name\":\"New\"}");
        OID4VPImportIdentityProviderConfig config = providerConfig(IdentityProviderSyncMode.FORCE);

        assertThrows(
                IllegalStateException.class,
                () -> provisioner.verifyAndSynchronizeExistingUser(request(claims), config, "external-id", user));

        verify(user, times(2)).setFirstName("New");
        verify(transactions).setRollbackOnly();
    }

    private OID4VPUserProvisioner.Request request(JsonNode claims) {
        return new OID4VPUserProvisioner.Request(
                session, realm, authenticator, context, null, primaryRequirement, null, claims, Map.of(), null);
    }

    private OID4VPImportIdentityProviderConfig providerConfig(IdentityProviderSyncMode syncMode) {
        OID4VPImportIdentityProviderConfig config = new OID4VPImportIdentityProviderConfig();
        config.setAlias(ALIAS);
        config.setEnabled(true);
        config.setSyncMode(syncMode);
        return config;
    }

    private static IdentityProviderMapperModel emailMapper() {
        return mapper("email-mapper", "email", "email", null);
    }

    private static IdentityProviderMapperModel firstNameMapper() {
        return mapper("first-name-mapper", "given_name", "firstName", null);
    }

    private static IdentityProviderMapperModel mapper(
            String name, String claim, String attribute, IdentityProviderMapperSyncMode syncMode) {
        IdentityProviderMapperModel model = new IdentityProviderMapperModel();
        model.setName(name);
        model.setIdentityProviderAlias(ALIAS);
        model.setIdentityProviderMapper(OID4VPUserAttributeMapper.PROVIDER_ID);
        model.setConfig(new HashMap<>(
                Map.of(AbstractOID4VPClaimMapper.CLAIM, claim, OID4VPUserAttributeMapper.USER_ATTRIBUTE, attribute)));
        if (syncMode != null) {
            model.setSyncMode(syncMode);
        }
        return model;
    }
}
