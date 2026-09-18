package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.KeycloakTestContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.TestCryptoUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialIdentity;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.FailingOID4VPUserAttributeMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers.OID4VPUserAttributeMapper;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListTestServer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import jakarta.ws.rs.core.Response;
import java.net.URI;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * End-to-end proof of prompt-free user import: an externally issued mdoc or SD-JWT credential
 * with an unknown subject creates, links, and authenticates a Keycloak user when import is
 * enabled, and is rejected without side effects when import is disabled.
 */
public class OID4VPUserImportTest extends OID4VPBaseUserAuthEndpointTest {

    private static final String TEST_ISSUER = TEST_MDOC_ISSUER;
    private static final String EXTERNAL_SUBJECT = "external-sub-1";
    private static final String EXTERNAL_SDJWT_SUBJECT = "external-sdjwt-sub";
    private static final String IMPORT_PROFILE_ID = "mdoc-import";
    private static final String SDJWT_IMPORT_PROFILE_ID = "sdjwt-import";

    @AfterEach
    void cleanUpImportedArtifacts() {
        for (String username : List.of(
                EXTERNAL_SUBJECT,
                "external-sub-2",
                "shared-sub",
                "no-namespace-sub",
                "tampered-sub",
                "race-sub",
                "bind-sub",
                "realm-spoof-sub",
                EXTERNAL_SDJWT_SUBJECT)) {
            for (UserRepresentation user : getActiveTestRealmResource().users().search(username)) {
                getActiveTestRealmResource().users().get(user.getId()).remove();
            }
        }
        unlinkExternalUser("disabled-user-id");
        unlinkExternalUser(TEST_USER_ID);
        removeImportIdp();
    }

    @Test
    public void shouldImportUnknownExternalUser_WhenImportEnabled() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true)
                            .setTestUser(EXTERNAL_SUBJECT);
                    testSuccessfulAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken), opts);
                });

        String externalId = CredentialIdentity.externalId(TEST_ISSUER, EXTERNAL_SUBJECT);
        List<UserRepresentation> users = getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT);
        assertEquals(1, users.size(), "Exactly one user must have been imported");
        assertEquals(EXTERNAL_SUBJECT, users.getFirst().getUsername());
        assertEquals("external@example.com", users.getFirst().getEmail());
        assertEquals("Ada", users.getFirst().getFirstName());
        assertEquals("Lovelace", users.getFirst().getLastName());

        FederatedIdentityRepresentation link =
                getActiveTestRealmResource().users().get(users.getFirst().getId()).getFederatedIdentity().stream()
                        .filter(identity -> IMPORT_IDP_ALIAS.equals(identity.getIdentityProvider()))
                        .findFirst()
                        .orElse(null);
        assertNotNull(link, "Imported user must carry a federated identity link");
        assertEquals(externalId, link.getUserId());
    }

    @Test
    public void shouldImportUnknownExternalUser_FromEudiTrustedSdJwt() throws Exception {
        createImportIdpWithSdJwtMappers();
        EudiPidTrustListTestServer trustListServer = KeycloakTestContainer.eudiPidTrustListServer();
        trustListServer.serveSignedTrustList();
        KeyPair trustAnchorKey = new KeyPair(
                MdocBaseTest.getIssuerCertRef1().getPublicKey(),
                MdocBaseTest.getIssuerKeyRef1().toECPrivateKey());
        KeyPair issuerKey = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        var issuerCertificate = TestCryptoUtils.createLeafCert(
                issuerKey, trustAnchorKey, MdocBaseTest.getIssuerCertRef1(), "CN=External SD-JWT PID Issuer");

        withAuthenticationProfile(
                sdJwtImportProfileJson(trustListServer),
                SDJWT_IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String credential = sdJwtVPTestUtils.requestExternalSdJwtCredential(
                            EudiPidTrustListTestServer.PROVIDER_A_ID,
                            OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT,
                            EXTERNAL_SDJWT_SUBJECT,
                            "external-sdjwt@example.com",
                            "Grace",
                            "Hopper",
                            issuerKey.getPrivate(),
                            List.of(issuerCertificate, MdocBaseTest.getIssuerCertRef1()));
                    String presentation = sdJwtVPTestUtils.presentSdJwt(
                            credential,
                            requestObject.getNonce(),
                            requestObject.getClientId(),
                            SdJwtVPTestUtils.getUserJwk());

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true)
                            .setTestUser(EXTERNAL_SDJWT_SUBJECT);
                    testSuccessfulAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, presentation), opts);
                });

        List<UserRepresentation> users = getActiveTestRealmResource().users().search(EXTERNAL_SDJWT_SUBJECT);
        assertEquals(1, users.size(), "Exactly one user must be imported from the external SD-JWT");
        assertEquals("external-sdjwt@example.com", users.getFirst().getEmail());
        assertEquals("Grace", users.getFirst().getFirstName());
        assertEquals("Hopper", users.getFirst().getLastName());
        FederatedIdentityRepresentation link =
                usersFederatedLink(users.getFirst().getId());
        assertNotNull(link);
        assertEquals(
                CredentialIdentity.externalId(EudiPidTrustListTestServer.PROVIDER_A_ID, EXTERNAL_SDJWT_SUBJECT),
                link.getUserId());
    }

    @Test
    public void shouldRollbackUserAndLink_WhenMapperFailsAfterCreation() throws Exception {
        createImportIdpWithMappers();
        addClaimMapper(
                "deliberate-post-write-failure",
                namespacedClaim("email"),
                "failure-probe",
                FailingOID4VPUserAttributeMapper.PROVIDER_ID);

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);
                    HttpResponse response = sendAuthorizationResponseWithVPTokenFlatMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            requestObject,
                            TestOpts.getDefault().setShouldForceUnencryptedResponse(true));
                    assertTrue(
                            response.getStatusLine().getStatusCode() >= HttpStatus.SC_BAD_REQUEST,
                            "A post-write mapper failure must fail the wallet response");
                    EntityUtils.consume(response.getEntity());
                });

        assertTrue(
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).isEmpty(),
                "The failed transaction must not leave an imported user or federated link");
    }

    @Test
    public void shouldRollbackLinkedUserChanges_WhenMapperFailsDuringRelogin() throws Exception {
        createImportIdpWithMappers();
        String userId = loginExternalUser();
        addClaimMapper(
                "deliberate-sync-failure",
                namespacedClaim("email"),
                "failure-probe",
                FailingOID4VPUserAttributeMapper.PROVIDER_ID);

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, EXTERNAL_SUBJECT, "changed@example.com");
                    HttpResponse response = sendAuthorizationResponseWithVPTokenFlatMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            requestObject,
                            TestOpts.getDefault().setShouldForceUnencryptedResponse(true));
                    assertTrue(
                            response.getStatusLine().getStatusCode() >= HttpStatus.SC_BAD_REQUEST,
                            "A linked-user mapper failure must fail authentication");
                    EntityUtils.consume(response.getEntity());
                });

        UserRepresentation user =
                getActiveTestRealmResource().users().get(userId).toRepresentation();
        assertEquals("external@example.com", user.getEmail(), "Failed synchronization must roll back user changes");
    }

    @Test
    public void shouldFailAuthentication_IfUserUnknown_WhenImportDisabled() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(importProfileJson(), IMPORT_PROFILE_ID, (apiFlow, requestObject) -> {
            String mdocToken = presentExternalMdoc(requestObject);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);
            testFailingAuthenticationWithVPTokenMap(
                    Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                    opts,
                    HttpStatus.SC_UNAUTHORIZED,
                    ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                    "User with presented OID4VP credential is unknown");
        });

        assertTrue(
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).isEmpty(),
                "No user may be created when import is disabled");
    }

    @Test
    public void shouldReuseLinkedUser_OnRelogin() throws Exception {
        createImportIdpWithMappers();

        String firstUserId = loginExternalUser();
        String secondUserId = loginExternalUser();

        assertEquals(firstUserId, secondUserId, "Relogin must resolve the same linked user");
        assertEquals(
                1,
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).size(),
                "Relogin must not create a duplicate user");
    }

    @Test
    public void shouldReuseLinkedUser_AfterImportDisabled() throws Exception {
        createImportIdpWithMappers();
        String importedUserId = loginExternalUser();

        // Turning import off prevents creation, never login: the linked user still authenticates.
        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "false"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true)
                            .setTestUser(EXTERNAL_SUBJECT);
                    testSuccessfulAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken), opts);
                });

        List<UserRepresentation> users = getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT);
        assertEquals(1, users.size(), "No duplicate may be created while import is disabled");
        assertEquals(importedUserId, users.getFirst().getId(), "The same linked user must authenticate");
    }

    @Test
    public void shouldNotSynchronizeLinkedUser_WhenUserAttributeBindingFails() throws Exception {
        createImportIdpWithMappers();
        String importedUserId = loginExternalUser();

        // The stored email is external@example.com. A later credential presents a different email
        // and requires it to match the stored user. Synchronizing first would overwrite the email
        // and make this invalid presentation pass its own binding check.
        withAuthenticationProfile(
                importProfileJsonWithEmailBinding(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, EXTERNAL_SUBJECT, "changed@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "Primary credential binding checks failed");
                });

        UserRepresentation user =
                getActiveTestRealmResource().users().get(importedUserId).toRepresentation();
        assertEquals(
                "external@example.com",
                user.getEmail(),
                "A failed binding must leave the linked user's attributes unchanged");
    }

    @Test
    public void shouldNotCreateLink_ForSameRealmUser() throws Exception {
        // Same-realm SD-JWT login succeeds without any federated link, even with import enabled.
        withImportEnabled(() -> {
            String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(
                    OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER_ID, TEST_USER);
            testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
        });

        assertTrue(
                getActiveTestRealmResource()
                        .users()
                        .get(TEST_USER_ID)
                        .getFederatedIdentity()
                        .isEmpty(),
                "Same-realm login must not create a federated link");
    }

    @Test
    public void shouldNotCreateUser_WhenPresentationInvalid() throws Exception {
        // An anchor the issuer certificate does not chain to fails trust validation:
        // with import enabled, nothing may be written.
        withAuthenticationProfile(
                AuthenticationProfileSamples.mdocPrimaryWithAnchor(MdocBaseTest.getSpecSampleCert()),
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    Map<String, Object> claims =
                            Map.of(MdocBaseTest.NAMESPACE, Map.of("sub", "tampered-sub", "username", "tampered-sub"));
                    String mdocToken = presentMdoc(requestObject, claims);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "Certificate chain validation failed");
                });

        assertTrue(
                getActiveTestRealmResource().users().search("tampered-sub").isEmpty(),
                "No user may be created from an invalid presentation");
    }

    @Test
    public void shouldNotImport_WhenImportIdpHasWrongProviderId() throws Exception {
        IdentityProviderRepresentation impostor = new IdentityProviderRepresentation();
        impostor.setAlias(IMPORT_IDP_ALIAS);
        impostor.setProviderId("oidc");
        impostor.setEnabled(true);
        getActiveTestRealmResource().identityProviders().create(impostor);

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "User with presented OID4VP credential is unknown");
                });

        assertTrue(
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).isEmpty(),
                "No user may be created against a foreign provider id");
    }

    @Test
    public void shouldNotImport_WhenUsernameTaken() throws Exception {
        createImportIdpWithMappers();
        String ownerId = createUser(EXTERNAL_SUBJECT, "owner@example.com");

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, EXTERNAL_SUBJECT, "newcomer@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "already exists");
                });

        assertEquals(
                1,
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).size(),
                "No second user may be created on username collision");
        assertTrue(
                getActiveTestRealmResource()
                        .users()
                        .get(ownerId)
                        .getFederatedIdentity()
                        .isEmpty(),
                "The pre-existing account must not gain a federated link");
    }

    @Test
    public void shouldNotImport_WhenEmailTaken() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, "external-sub-2", "test-user@localhost");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "already exists");
                });

        assertTrue(
                getActiveTestRealmResource().users().search("external-sub-2").isEmpty(),
                "No user may be created on email collision");
        assertTrue(
                getActiveTestRealmResource()
                        .users()
                        .get(TEST_USER_ID)
                        .getFederatedIdentity()
                        .isEmpty(),
                "The pre-existing account must not gain a federated link");
    }

    @Test
    public void shouldNotRecreateDeletedUser_WhenImportEnabled() throws Exception {
        // Same-realm SD-JWT credential whose subject matches no user: import stays off-limits,
        // the missing account is never recreated.
        withImportEnabled(() -> {
            String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(
                    OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT, "deleted-sub-id", "deleted-user");
            testFailingAuthentication(
                    sdJwt,
                    TestOpts.getDefault(),
                    HttpStatus.SC_UNAUTHORIZED,
                    ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                    "User with presented OID4VP credential is unknown");
        });

        assertTrue(
                getActiveTestRealmResource().users().search("deleted-user").isEmpty(),
                "No user may be recreated from an old credential");
    }

    @Test
    public void shouldNotLinkExternalSubjectMatchingLocalId() throws Exception {
        createImportIdp();
        String localId = TEST_USER_ID;

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    // Same sub value as the local user id, but externally issued: must never
                    // authenticate as, or link to, the local account.
                    String mdocToken = presentExternalMdoc(requestObject, localId, "attacker@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "Staged user data violates the realm user profile");
                });

        assertTrue(
                getActiveTestRealmResource()
                        .users()
                        .get(TEST_USER_ID)
                        .getFederatedIdentity()
                        .isEmpty(),
                "The local account must not gain a federated link");
        assertTrue(
                getActiveTestRealmResource().users().search("test-user-id").isEmpty(),
                "No squat account may be created for the local user id");
    }

    @Test
    public void shouldNotCreateUser_WhenStagedBindingFails() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                importProfileJsonWithUsernameMismatchBinding(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    // Staged username derives from "bind-sub" while the credential email is
                    // different, so the primary user-attribute binding fails before creation.
                    String mdocToken = presentExternalMdoc(requestObject, "bind-sub", "other@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "Staged user data violates a credential binding rule");
                });

        assertTrue(
                getActiveTestRealmResource().users().search("bind-sub").isEmpty(),
                "No user may be created when a staged binding fails");
    }

    @Test
    public void shouldRejectExternalCredentialClaimingRealmIssuer() throws Exception {
        createImportIdpWithMappers();
        String realmIssuer = getTestRealmEndpoint();

        withAuthenticationProfile(
                importProfileJson(IMPORT_PROFILE_ID, realmIssuer),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    // Externally verified (x5c trust) but namespaced as this realm: the spoof
                    // guard must reject it during verification, before any user lookup.
                    String mdocToken = presentExternalMdoc(requestObject, "realm-spoof-sub", "spoof@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "must not claim");
                });

        assertTrue(
                getActiveTestRealmResource().users().search("realm-spoof-sub").isEmpty(),
                "No user may be created from a spoofed realm issuer");
    }

    @Test
    public void shouldNotImport_WhenIssuerNamespaceMissing() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                AuthenticationProfileSamples.mdocPrimary(),
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    // Pinned x5c trust without an explicit issuer: no stable external identity,
                    // so import fails closed even when enabled.
                    Map<String, Object> claims = Map.of(
                            MdocBaseTest.NAMESPACE, Map.of("sub", "no-namespace-sub", "username", "no-namespace-sub"));
                    String mdocToken = presentMdoc(requestObject, claims);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "User with presented OID4VP credential is unknown");
                });

        assertTrue(
                getActiveTestRealmResource().users().search("no-namespace-sub").isEmpty(),
                "No user may be created without a stable issuer namespace");
    }

    @Test
    public void shouldNotImport_WhenImportIdpMissing() throws Exception {
        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "User with presented OID4VP credential is unknown");
                });

        assertTrue(
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).isEmpty(),
                "No user may be created without the import provider");
    }

    @Test
    public void shouldNotImport_WhenImportIdpDisabled() throws Exception {
        createImportIdp();
        IdentityProviderRepresentation idp = getActiveTestRealmResource()
                .identityProviders()
                .get(IMPORT_IDP_ALIAS)
                .toRepresentation();
        idp.setEnabled(false);
        getActiveTestRealmResource().identityProviders().get(IMPORT_IDP_ALIAS).update(idp);

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "User with presented OID4VP credential is unknown");
                });

        assertTrue(
                getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT).isEmpty(),
                "No user may be created while the import provider is disabled");
    }

    @Test
    public void shouldRejectDisabledLinkedUser() throws Exception {
        // The link requires its IdP to exist; no mappers are needed since synchronization
        // is skipped for disabled accounts.
        createImportIdp();
        linkExternalUser("disabled-user-id", TEST_ISSUER, "disabled-sub");

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, "disabled-sub", "disabled-user@localhost");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "disabled");
                });

        assertEquals(
                false,
                getActiveTestRealmResource()
                        .users()
                        .get("disabled-user-id")
                        .toRepresentation()
                        .isEnabled(),
                "The disabled account must remain disabled");
    }

    @Test
    public void shouldFailSecondIssuer_WhenSubjectSharedAcrossIssuers() throws Exception {
        createImportIdpWithMappers();
        String firstUserId = loginExternalSubject(IMPORT_PROFILE_ID, TEST_ISSUER, "shared-sub", "shared@example.com");

        // Same subject from another issuer: never the same identity. Tier 1 cannot offer link
        // confirmation, so the colliding import fails safely instead of taking anything over.
        withAuthenticationProfile(
                importProfileJson(IMPORT_PROFILE_ID, "test-mdoc-issuer-b"),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, "shared-sub", "shared-b@example.com");

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);
                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "already exists");
                });

        assertEquals(
                1,
                getActiveTestRealmResource().users().search("shared-sub").size(),
                "No second user may be created for the shared subject");
        assertEquals(
                1,
                getActiveTestRealmResource()
                        .users()
                        .get(firstUserId)
                        .getFederatedIdentity()
                        .size(),
                "The first account must keep exactly its own link");
    }

    @Test
    public void shouldImportUnknownExternalUser_InBrowserSameDeviceFlow() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                importProfileJson("default", TEST_ISSUER),
                "default",
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    FormData formData = getFreshOid4vpFormActionUrl(false);
                    AuthorizationContext browserContext = formData.authContextSameDevice();
                    RequestObject browserRequest = resolveRequestObject(browserContext.getAuthorizationRequest());
                    String mdocToken = presentExternalMdoc(browserRequest);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(browserContext)
                            .setCodeVerifier(formData.oid4vpCodeVerifier())
                            .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier())
                            .setTestUser(EXTERNAL_SUBJECT)
                            .setShouldRetrieveAccessToken(false);
                    TestFlowData flow = testSuccessfulAuthenticationWithVPTokenMapVerbose(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken), opts);

                    String redirectUri = flow.responseToWallet().getRedirectUri();
                    assertNotNull(redirectUri, "Same-device response must redirect back to Keycloak");
                    assertTrue(
                            redirectUri.contains(OID4VPUserAuthEndpoint.CALLBACK_URI_PATH),
                            "Redirect URI should be on callback path");

                    try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                            .setDefaultCookieStore(formData.cookieStore())
                            .disableRedirectHandling()
                            .build()) {
                        HttpResponse callbackResponse = httpClient.execute(new HttpGet(redirectUri));
                        String redirectActionUri = captureNextRedirect(callbackResponse);

                        ResteasyUriInfo uriInfo = new ResteasyUriInfo(URI.create(redirectActionUri));
                        String authCode = uriInfo.getQueryParameters().getFirst(OAuth2Constants.CODE);

                        HttpResponse actionResponse = httpClient.execute(new HttpGet(redirectActionUri));
                        String freshAuthCode = extractAuthCodeInRedirect(actionResponse);

                        assertAuthenticatingUser(opts.setShouldEnforceRedirectUri(true), freshAuthCode);
                        assertNotEquals(authCode, freshAuthCode);
                    }
                });

        String externalId = CredentialIdentity.externalId(TEST_ISSUER, EXTERNAL_SUBJECT);
        List<UserRepresentation> users = getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT);
        assertEquals(1, users.size(), "Exactly one user must have been imported via the browser flow");
        FederatedIdentityRepresentation link =
                usersFederatedLink(users.getFirst().getId());
        assertNotNull(link, "Imported user must carry a federated identity link");
        assertEquals(externalId, link.getUserId());
    }

    @Test
    public void shouldImportUnknownExternalUser_InBrowserCrossDeviceFlow() throws Exception {
        createImportIdpWithMappers();

        withAuthenticationProfile(
                importProfileJson("default", TEST_ISSUER),
                "default",
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    FormData formData = getFreshOid4vpFormActionUrl(true);
                    AuthorizationContext browserContext = formData.authContext();
                    RequestObject browserRequest = resolveRequestObject(browserContext.getAuthorizationRequest());
                    String mdocToken = presentExternalMdoc(browserRequest);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(browserContext)
                            .setCodeVerifier(formData.oid4vpCodeVerifier())
                            .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier())
                            .setTestUser(EXTERNAL_SUBJECT)
                            .setShouldRetrieveAccessToken(false);
                    String authCode = testSuccessfulAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken), opts);

                    try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                            .setDefaultCookieStore(formData.cookieStore())
                            .build()) {
                        HttpPost completion = new HttpPost(formData.actionUrl());
                        completion.setEntity(new UrlEncodedFormEntity(
                                List.of(new BasicNameValuePair(OAuth2Constants.CODE, authCode))));
                        String freshAuthCode = extractAuthCodeInRedirect(httpClient.execute(completion));
                        assertAuthenticatingUser(opts.setShouldEnforceRedirectUri(true), freshAuthCode);
                        assertNotEquals(authCode, freshAuthCode, "The browser flow must issue a fresh OIDC code");
                    }
                });

        List<UserRepresentation> users = getActiveTestRealmResource().users().search(EXTERNAL_SUBJECT);
        assertEquals(1, users.size(), "Exactly one user must have been imported via the QR flow");
        assertNotNull(usersFederatedLink(users.getFirst().getId()));
    }

    @Test
    public void concurrentImportsCreateAtMostOneUser() throws Exception {
        createImportIdpWithMappers();
        int parties = 3;

        withAuthenticationProfile(
                importProfileJson(),
                IMPORT_PROFILE_ID,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    // One authorization flow per party, then a gated simultaneous wallet response.
                    // Every interleaving must end with a single user: the link recheck, the
                    // username uniqueness constraint, and rollback-only escape cover all losers.
                    List<ApiFlowData> flows = new ArrayList<>();
                    List<RequestObject> requests = new ArrayList<>();
                    flows.add(apiFlow);
                    requests.add(requestObject);
                    for (int i = 1; i < parties; i++) {
                        ApiFlowData extra = startApiAuthorizationRequest(IMPORT_PROFILE_ID);
                        flows.add(extra);
                        requests.add(resolveRequestObject(extra.authContext().getAuthorizationRequest()));
                    }

                    CountDownLatch ready = new CountDownLatch(parties);
                    CountDownLatch go = new CountDownLatch(1);
                    ExecutorService pool = Executors.newFixedThreadPool(parties);
                    try {
                        List<Future<Boolean>> outcomes = new ArrayList<>();
                        for (int i = 0; i < parties; i++) {
                            RequestObject partyRequest = requests.get(i);
                            outcomes.add(pool.submit(() -> {
                                String token = presentExternalMdoc(partyRequest, "race-sub", "race@example.com");
                                ready.countDown();
                                if (!go.await(60, TimeUnit.SECONDS)) {
                                    return false;
                                }
                                // Consume the entity so the shared client's pooled connection is
                                // released; otherwise concurrent parties starve the pool.
                                HttpResponse response = sendAuthorizationResponseWithVPTokenFlatMap(
                                        Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, token),
                                        partyRequest,
                                        TestOpts.getDefault().setShouldForceUnencryptedResponse(true));
                                EntityUtils.consume(response.getEntity());
                                return response.getStatusLine().getStatusCode() == HttpStatus.SC_OK;
                            }));
                        }
                        assertTrue(ready.await(60, TimeUnit.SECONDS), "All parties must reach the gate");
                        go.countDown();

                        int successes = 0;
                        for (Future<Boolean> outcome : outcomes) {
                            if (outcome.get(120, TimeUnit.SECONDS)) {
                                successes++;
                            }
                        }
                        assertTrue(successes >= 1, "At least one concurrent import must succeed");
                    } finally {
                        pool.shutdownNow();
                    }
                });

        assertEquals(
                1,
                getActiveTestRealmResource().users().search("race-sub").size(),
                "Concurrent imports must leave exactly one user and link");
    }

    private FederatedIdentityRepresentation usersFederatedLink(String userId) {
        return getActiveTestRealmResource().users().get(userId).getFederatedIdentity().stream()
                .filter(identity -> IMPORT_IDP_ALIAS.equals(identity.getIdentityProvider()))
                .findFirst()
                .orElse(null);
    }

    private String createUser(String username, String email) {
        UserRepresentation representation = new UserRepresentation();
        representation.setUsername(username);
        representation.setEmail(email);
        representation.setEnabled(true);
        try (Response response = getActiveTestRealmResource().users().create(representation)) {
            assertEquals(201, response.getStatus());
        }
        return getActiveTestRealmResource().users().search(username).getFirst().getId();
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private void withImportEnabled(ThrowingRunnable test) throws Exception {
        AuthenticatorConfigRepresentation originalConfig = getAuthenticatorConfig();
        try {
            AuthenticatorConfigRepresentation updatedConfig = getAuthenticatorConfig();
            updatedConfig.getConfig().put(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true");
            updateAuthenticatorConfig(updatedConfig);
            test.run();
        } finally {
            updateAuthenticatorConfig(originalConfig);
        }
    }

    private String presentMdoc(RequestObject requestObject, Map<String, Object> claims) throws Exception {
        return MdocBaseTest.buildMdocVpToken(requestObject, claims, MdocBaseTest.DOC_TYPE);
    }

    private String loginExternalUser() throws Exception {
        return loginExternalSubject(IMPORT_PROFILE_ID, TEST_ISSUER, EXTERNAL_SUBJECT, "external@example.com");
    }

    private String loginExternalSubject(String profileId, String issuer, String subject, String email)
            throws Exception {
        withAuthenticationProfile(
                importProfileJson(profileId, issuer),
                profileId,
                Map.of(OID4VPAuthenticatorFactory.IMPORT_UNKNOWN_USERS_CONFIG, "true"),
                (apiFlow, requestObject) -> {
                    String mdocToken = presentExternalMdoc(requestObject, subject, email);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true)
                            .setTestUser(subject);
                    testSuccessfulAuthenticationWithVPTokenMap(
                            Map.of(AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID, mdocToken), opts);
                });
        return getActiveTestRealmResource().users().search(subject).getFirst().getId();
    }

    private String importProfileJson() {
        return importProfileJson(IMPORT_PROFILE_ID, TEST_ISSUER);
    }

    private String importProfileJsonWithEmailBinding() {
        return importProfileJson()
                .replace(
                        "\"subjectClaim\": \"{namespace}/sub\",".replace("{namespace}", MdocBaseTest.NAMESPACE),
                        """
                "subjectClaim": "{namespace}/sub",
                        "binding": [
                          {
                            "type": "claim_equals_user_attribute",
                            "credentialClaim": "{namespace}/email",
                            "userAttribute": "email"
                          }
                        ],
                """.replace("{namespace}", MdocBaseTest.NAMESPACE));
    }

    /**
     * Primary binding requiring the credential email to equal the staged username. Since the
     * staged username derives from the subject, any credential whose email differs from its
     * subject fails its staged binding check before any user is created.
     */
    private String importProfileJsonWithUsernameMismatchBinding() {
        return importProfileJson()
                .replace(
                        "\"subjectClaim\": \"{namespace}/sub\",".replace("{namespace}", MdocBaseTest.NAMESPACE),
                        """
                "subjectClaim": "{namespace}/sub",
                        "binding": [
                          {
                            "type": "claim_equals_user_attribute",
                            "credentialClaim": "{namespace}/email",
                            "userAttribute": "username"
                          }
                        ],
                """.replace("{namespace}", MdocBaseTest.NAMESPACE));
    }

    private String importProfileJson(String profileId, String issuer) {
        return """
                [
                  {
                    "id": "{profileId}",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "mso_mdoc",
                        "credentialTypes": ["{docType}"],
                        "claims": ["{namespace}/sub", "{namespace}/email", "{namespace}/given_name", "{namespace}/family_name"],
                        "subjectClaim": "{namespace}/sub",
                        "trust": [
                          { "type": "x5c", "anchors": ["{anchor}"], "issuer": "{issuer}" }
                        ]
                      }
                    ]
                  }
                ]
                """.replace("{profileId}", profileId)
                .replace("{docType}", MdocBaseTest.DOC_TYPE)
                .replace("{namespace}", MdocBaseTest.NAMESPACE)
                .replace("{anchor}", MdocBaseTest.getIssuerCertBase64())
                .replace("{issuer}", issuer);
    }

    private void createImportIdpWithMappers() {
        createImportIdp();

        addClaimMapper("external-email", namespacedClaim("email"), "email");
        addClaimMapper("external-first-name", namespacedClaim("given_name"), "firstName");
        addClaimMapper("external-last-name", namespacedClaim("family_name"), "lastName");
    }

    private void createImportIdpWithSdJwtMappers() {
        createImportIdp();
        addClaimMapper("external-email", "email", "email");
        addClaimMapper("external-first-name", "given_name", "firstName");
        addClaimMapper("external-last-name", "family_name", "lastName");
    }

    private String sdJwtImportProfileJson(EudiPidTrustListTestServer trustListServer) {
        return """
                [
                  {
                    "id": "{profileId}",
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "format": "dc+sd-jwt",
                        "credentialTypes": ["{vct}"],
                        "claims": ["sub", "email", "given_name", "family_name"],
                        "subjectClaim": "sub",
                        "trust": [
                          {
                            "type": "eudi_pid_trust_list",
                            "trustListUrl": "{trustListUrl}",
                            "trustListSigningCertificate": "{trustListSigningCertificate}",
                            "serviceType": "http://uri.etsi.org/19602/SvcType/PID/Issuance",
                            "issuer": "{issuer}"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """.replace("{profileId}", SDJWT_IMPORT_PROFILE_ID)
                .replace("{vct}", OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT)
                .replace("{trustListUrl}", trustListServer.urlFromKeycloakContainer())
                .replace("{trustListSigningCertificate}", MdocBaseTest.getIssuerCertBase64())
                .replace("{issuer}", EudiPidTrustListTestServer.PROVIDER_A_ID);
    }

    private static String namespacedClaim(String element) {
        // The mDoc namespace itself contains dots, so it must be escaped in claim paths.
        return MdocBaseTest.NAMESPACE.replace(".", "\\.") + "." + element;
    }

    private void addClaimMapper(String name, String claim, String userAttribute) {
        addClaimMapper(name, claim, userAttribute, OID4VPUserAttributeMapper.PROVIDER_ID);
    }

    private void addClaimMapper(String name, String claim, String userAttribute, String providerId) {
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(name);
        mapper.setIdentityProviderAlias(IMPORT_IDP_ALIAS);
        mapper.setIdentityProviderMapper(providerId);
        mapper.setConfig(Map.of("claim", claim, "user.attribute", userAttribute));
        getActiveTestRealmResource().identityProviders().get(IMPORT_IDP_ALIAS).addMapper(mapper);
    }

    private String presentExternalMdoc(RequestObject requestObject) throws Exception {
        return presentExternalMdoc(requestObject, EXTERNAL_SUBJECT, "external@example.com");
    }

    private String presentExternalMdoc(RequestObject requestObject, String subject, String email) throws Exception {
        Map<String, Object> claims = Map.of(
                MdocBaseTest.NAMESPACE,
                Map.of("sub", subject, "email", email, "given_name", "Ada", "family_name", "Lovelace"));
        return MdocBaseTest.buildMdocVpToken(requestObject, claims, MdocBaseTest.DOC_TYPE);
    }
}
