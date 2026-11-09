package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.OpenId4VpConstants.PRESENTATION_VERIFIED_NOTE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.GuardedCredentialScopeTest.clientScope;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.OPENID_CREDENTIAL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationVerifiedNote;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.utils.EncryptedPayloadUtils;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.models.oid4vci.CredentialScopeModel;
import org.keycloak.protocol.oid4vc.issuance.OID4VCAuthorizationDetailsProcessor;
import org.keycloak.protocol.oid4vc.issuance.credentialbuilder.CredentialBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.ErrorType;
import org.keycloak.protocol.oid4vc.model.OID4VCAuthorizationDetail;
import org.keycloak.protocol.oidc.rar.AuthorizationDetailsProcessor;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.util.JsonSerialization;

public class PatchedOID4VCIssuerEndpointTest {

    private static final String SUBJECT_ONLY = "{\"credential_configuration_id\": \"my-config\"}";
    private static final String IDENTIFIER_ONLY = "{\"credential_identifier\": \"my-id\"}";
    private static final String SUBJECT_AND_IDENTIFIER =
            "{\"credential_configuration_id\": \"my-config\", \"credential_identifier\": \"my-id\"}";

    /**
     * Covers the dispatch added for unauthenticated requests: the payload must reach the core
     * endpoint byte-for-byte (no patching, no gate) instead of being touched by this endpoint.
     */
    @Nested
    class UnauthenticatedRequestDispatch {

        private final Response superResponse = mock(Response.class);
        private String forwardedToSuper;

        private PatchedOID4VCIssuerEndpoint authenticatedEndpoint() {
            return new MockPatchedOID4VCIssuerEndpoint("true", null) {
                @Override
                protected Response forwardToCoreEndpoint(String requestPayload) {
                    forwardedToSuper = requestPayload;
                    return UnauthenticatedRequestDispatch.this.superResponse;
                }
            };
        }

        @Test
        public void shouldForwardOriginalPayloadToCoreEndpointWhenRequestIsUnauthenticated() {
            Response response = authenticatedEndpoint().requestCredential(SUBJECT_ONLY);
            // The core endpoint received the payload exactly as the wallet sent it.
            assertEquals(SUBJECT_ONLY, forwardedToSuper);
            // The response is the one produced by the core endpoint, passed through untouched.
            assertSame(superResponse, response);
        }
    }

    @Nested
    class PatchWalletRequest {

        private final PatchedOID4VCIssuerEndpoint endpoint = new MockPatchedOID4VCIssuerEndpoint();

        @Test
        public void shouldPatchWhenOnlyConfigurationIdSent() throws Exception {
            CredentialRequest req =
                    JsonSerialization.readValue(endpoint.patchWalletRequest(SUBJECT_ONLY), CredentialRequest.class);

            assertEquals("my-config", req.getCredentialIdentifier());
            assertNull(req.getCredentialConfigurationId());
        }

        @Test
        public void shouldKeepRequestUnchangedWhenIdentifierSent() {
            assertEquals(IDENTIFIER_ONLY, endpoint.patchWalletRequest(IDENTIFIER_ONLY));
            assertEquals(SUBJECT_AND_IDENTIFIER, endpoint.patchWalletRequest(SUBJECT_AND_IDENTIFIER));
        }

        @Test
        public void shouldForwardUntouchablePayloadsAsIs() {
            // Null and empty.
            assertNull(endpoint.patchWalletRequest(null));
            assertEquals("", endpoint.patchWalletRequest(""));

            // Not parseable JSON.
            String invalidJson = "{\"invalid\": ";
            assertEquals(invalidJson, endpoint.patchWalletRequest(invalidJson));

            // Whitespace-only payload.
            String whitespace = "   ";
            assertEquals(whitespace, endpoint.patchWalletRequest(whitespace));
        }

        @Test
        public void shouldNotPatchWhenAttributeDisabledOrAbsent() {
            assertEquals(
                    SUBJECT_ONLY, new MockPatchedOID4VCIssuerEndpoint(null, null).patchWalletRequest(SUBJECT_ONLY));
            assertEquals(
                    SUBJECT_ONLY, new MockPatchedOID4VCIssuerEndpoint("false", null).patchWalletRequest(SUBJECT_ONLY));
        }
    }

    /**
     * Covers JWE-encrypted (OID4VCI §10) Credential Requests, mirroring the plaintext cases in
     * {@link PatchWalletRequest}. The wallet encrypts to the realm's {@code RSA-OAEP} encryption
     * key; the patch must decrypt, transcribe {@code credential_configuration_id} onto
     * {@code credential_identifier}, and re-encrypt so that agnostic wallets see an equivalent
     * ciphertext.
     */
    @Nested
    class PatchEncryptedCredentialRequests {

        private static KeyWrapper realmEncKey;

        @BeforeAll
        static void setUpCryptoAndRealmKey() throws Exception {
            if (!CryptoIntegration.isInitialised()) {
                CryptoIntegration.init(EncryptedPayloadUtils.class.getClassLoader());
            }

            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();

            realmEncKey = new KeyWrapper();
            realmEncKey.setKid(MockPatchedOID4VCIssuerEndpoint.TEST_KID);
            realmEncKey.setUse(KeyUse.ENC);
            realmEncKey.setAlgorithm(JWEConstants.RSA_OAEP);
            realmEncKey.setPrivateKey(keyPair.getPrivate());
            realmEncKey.setPublicKey(keyPair.getPublic());
        }

        private PatchedOID4VCIssuerEndpoint endpoint(String attributeValue, List<KeyWrapper> encKeys) {
            return new MockPatchedOID4VCIssuerEndpoint(attributeValue, encKeys);
        }

        @Test
        public void shouldDecryptPatchAndReEncryptEncryptedRequest() throws Exception {
            String original = encryptCredentialRequestJson(SUBJECT_ONLY);
            String patched = endpoint("true", List.of(realmEncKey)).patchWalletRequest(original);

            // The round-trip yields a fresh ciphertext, not the plaintext or the original JWE.
            assertNotEquals(original, patched);
            assertFalse(patched.startsWith("{"), "the patched request must remain encrypted");

            // The re-encrypted request decrypts back to the patched Credential Request...
            CredentialRequest req = decryptCredentialRequest(patched);
            assertEquals("my-config", req.getCredentialIdentifier());
            assertNull(req.getCredentialConfigurationId());

            // ...while preserving the original protected header parameters.
            JWEHeader header = readHeader(patched);
            assertEquals(MockPatchedOID4VCIssuerEndpoint.TEST_KID, header.getKeyId());
            assertEquals(JWEConstants.RSA_OAEP, header.getAlgorithm());
            assertEquals(JWEConstants.A256GCM, header.getEncryptionAlgorithm());
        }

        @Test
        public void shouldReturnEncryptedRequestUnchangedWhenIdentifierSent() throws Exception {
            String original1 = encryptCredentialRequestJson(IDENTIFIER_ONLY);
            assertEquals(original1, endpoint("true", List.of(realmEncKey)).patchWalletRequest(original1));

            String original2 = encryptCredentialRequestJson(SUBJECT_AND_IDENTIFIER);
            assertEquals(original2, endpoint("true", List.of(realmEncKey)).patchWalletRequest(original2));
        }

        @Test
        public void shouldForwardUntouchablePayloadsAsIs() {
            PatchedOID4VCIssuerEndpoint endpoint = endpoint("true", List.of(realmEncKey));

            // Null and empty.
            assertNull(endpoint.patchWalletRequest(null));
            assertEquals("", endpoint.patchWalletRequest(""));

            // Whitespace is not a JWE and not parseable JSON: forwarded untouched.
            assertEquals("   ", endpoint.patchWalletRequest("   "));

            // Five garbage segments decodable as base64url but not as a JOSE header.
            String garbage = base64Url("garbage") + "." + base64Url("cek") + "." + base64Url("iv") + "."
                    + base64Url("ct") + "." + base64Url("tag");
            assertEquals(garbage, endpoint.patchWalletRequest(garbage));

            // Not a JWE at all.
            assertEquals("not-a-jwe", endpoint.patchWalletRequest("not-a-jwe"));
        }

        @Test
        public void shouldNotPatchWhenAttributeAbsentOrDisabled() throws Exception {
            PatchedOID4VCIssuerEndpoint endpoint1 = endpoint(null, List.of(realmEncKey));

            assertEquals(SUBJECT_ONLY, endpoint1.patchWalletRequest(SUBJECT_ONLY));

            PatchedOID4VCIssuerEndpoint endpoint2 = endpoint("false", List.of(realmEncKey));

            String encrypted = encryptCredentialRequestJson(SUBJECT_ONLY);
            assertEquals(encrypted, endpoint2.patchWalletRequest(encrypted));

            assertEquals(SUBJECT_ONLY, endpoint2.patchWalletRequest(SUBJECT_ONLY));
        }

        @Test
        public void shouldForwardEncryptedRequestAsIsWhenNoEncryptionKeyMatchesKid() throws Exception {
            String original = encryptCredentialRequestJson(SUBJECT_ONLY);
            // No keys available in the realm at all -> resolution fails -> forwarded untouched.
            assertEquals(original, endpoint("true", List.of()).patchWalletRequest(original));
        }

        @Test
        public void shouldForwardEncryptedRequestAsIsWhenMultipleKeysMatchKid() throws Exception {
            String original = encryptCredentialRequestJson(SUBJECT_ONLY);
            List<KeyWrapper> duplicated = Stream.of(realmEncKey, realmEncKey).collect(Collectors.toList());
            assertEquals(original, endpoint("true", duplicated).patchWalletRequest(original));
        }

        @Test
        public void shouldForwardEncryptedRequestAsIsWhenCompressed() throws Exception {
            // zip=DEF requests are not supported: the patch must fail on them cleanly and leave
            // the compressed payload untouched instead of mangling deflate'd content into JSON.
            JWEHeader header = new JWEHeader.JWEHeaderBuilder()
                    .keyId(MockPatchedOID4VCIssuerEndpoint.TEST_KID)
                    .algorithm(JWEConstants.RSA_OAEP)
                    .encryptionAlgorithm(JWEConstants.A256GCM)
                    .compressionAlgorithm("DEF")
                    .type("JWT")
                    .build();
            JWE jwe = new JWE().header(header).content(SUBJECT_ONLY.getBytes(StandardCharsets.UTF_8));
            jwe.getKeyStorage().setEncryptionKey(realmEncKey.getPublicKey());
            String compressed = jwe.encodeJwe();

            assertEquals(compressed, endpoint("true", List.of(realmEncKey)).patchWalletRequest(compressed));
        }

        @Test
        public void shouldForwardEncryptedRequestAsIsWhenKidMissing() throws Exception {
            JWEHeader header = new JWEHeader.JWEHeaderBuilder()
                    .algorithm(JWEConstants.RSA_OAEP)
                    .encryptionAlgorithm(JWEConstants.A256GCM)
                    .type("JWT")
                    .build();
            JWE jwe = new JWE().header(header).content(SUBJECT_ONLY.getBytes(StandardCharsets.UTF_8));
            jwe.getKeyStorage().setEncryptionKey(realmEncKey.getPublicKey());
            String noKid = jwe.encodeJwe();

            assertEquals(noKid, endpoint("true", List.of(realmEncKey)).patchWalletRequest(noKid));
        }

        private String encryptCredentialRequestJson(String payloadJson) throws Exception {
            JWEHeader header = new JWEHeader.JWEHeaderBuilder()
                    .keyId(MockPatchedOID4VCIssuerEndpoint.TEST_KID)
                    .algorithm(JWEConstants.RSA_OAEP)
                    .encryptionAlgorithm(JWEConstants.A256GCM)
                    .type("JWT")
                    .build();
            JWE jwe = new JWE().header(header).content(payloadJson.getBytes(StandardCharsets.UTF_8));
            jwe.getKeyStorage().setEncryptionKey(realmEncKey.getPublicKey());
            return jwe.encodeJwe();
        }

        private CredentialRequest decryptCredentialRequest(String jweString) throws Exception {
            JWE jwe = new JWE(jweString);
            jwe.getKeyStorage().setDecryptionKey(realmEncKey.getPrivateKey());
            jwe.verifyAndDecodeJwe();
            return JsonSerialization.readValue(
                    new String(jwe.getContent(), StandardCharsets.UTF_8), CredentialRequest.class);
        }

        private static JWEHeader readHeader(String jweString) {
            return (JWEHeader) new JWE(jweString).getHeader();
        }

        private static String base64Url(String value) {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
        }
    }

    @Nested
    class IssuanceGateWithoutPresentation {

        static Stream<Arguments> unsupportedPresentations() {
            return Stream.of(
                    // No verified-presentation marker on the session at all.
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), null, null, null),
                    // A session verified via a mode the credential does not allow.
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), NESTED_OID4VP_FLOW, null, null),
                    // A credential that accepts several modes still blocks a session with no marker.
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION, NESTED_OID4VP_FLOW), null, null, null),
                    Arguments.of(List.of(), null, null, null),
                    // A supported mode does not save a presentation bound to another authentication profile.
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "other"),
                    // A supported mode without any bound profile fails when a profile is enforced.
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", null));
        }

        @ParameterizedTest(
                name = "gate_shouldBlock when scopeModes={0}, sessionMode={1}, scopeProfile={2}, noteProfile={3}")
        @MethodSource("unsupportedPresentations")
        public void shouldBlockWhenSessionLacksSupportedPresentation(
                List<PresentationDuringIssuanceMode> scopeModes,
                PresentationDuringIssuanceMode sessionMode,
                String scopeProfileId,
                String noteProfileId) {
            CredentialScopeModel scope = mockedScope(scopeModes, scopeProfileId);
            UserSessionModel session = sessionWithNote(sessionMode, noteProfileId);

            assertTrue(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
        }

        static Stream<Arguments> supportedPresentations() {
            return Stream.of(
                    Arguments.of(List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"),
                    Arguments.of(
                            List.of(INTERACTIVE_AUTHORIZATION, NESTED_OID4VP_FLOW),
                            INTERACTIVE_AUTHORIZATION,
                            "enforced",
                            "enforced"),
                    // Empty list = accept any mode, so the verified interactive mode is supported.
                    Arguments.of(List.of(), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"),
                    // The presentation matches the concrete authentication profile enforced by the credential.
                    Arguments.of(
                            List.of(INTERACTIVE_AUTHORIZATION), INTERACTIVE_AUTHORIZATION, "enforced", "enforced"));
        }

        @ParameterizedTest(
                name = "gate_shouldAllow when scopeModes={0}, sessionMode={1}, scopeProfile={2}, noteProfile={3}")
        @MethodSource("supportedPresentations")
        public void shouldAllowWhenSessionHasSupportedPresentation(
                List<PresentationDuringIssuanceMode> scopeModes,
                PresentationDuringIssuanceMode sessionMode,
                String scopeProfileId,
                String noteProfileId) {
            CredentialScopeModel scope = mockedScope(scopeModes, scopeProfileId);
            UserSessionModel session = sessionWithNote(sessionMode, noteProfileId);

            assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
        }

        @Test
        public void shouldAllowWhenNotGated() {
            // no requires_presentation attribute configured
            CredentialScopeModel scope = mockedScope(null, null);
            UserSessionModel session = sessionWithNote(null, null);

            assertFalse(PatchedOID4VCIssuerEndpoint.isIssuanceGatedWithoutPresentation(scope, session));
        }
    }

    @Nested
    class ResolveRequestedCredentialConfigurationId {

        @Test
        public void shouldRejectImmediatelyWhenAccessTokenGrantsMultipleCredentials() {
            MockPatchedOID4VCIssuerEndpoint endpoint = new MockPatchedOID4VCIssuerEndpoint();

            OID4VCAuthorizationDetailsProcessor processor = mock(OID4VCAuthorizationDetailsProcessor.class);
            when(processor.getSupportedAuthorizationDetails(any()))
                    .thenReturn(List.of(new OID4VCAuthorizationDetail(), new OID4VCAuthorizationDetail()));
            when(endpoint.getSession().getProvider(AuthorizationDetailsProcessor.class, OPENID_CREDENTIAL))
                    .thenReturn(processor);

            AuthenticationManager.AuthResult authResult = mock(AuthenticationManager.AuthResult.class);
            when(authResult.token()).thenReturn(mock(AccessToken.class));
            EventBuilder eventBuilder = endpoint.getEventBuilder();

            BadRequestException ex = assertThrows(
                    BadRequestException.class,
                    () -> endpoint.resolveRequestedCredentialConfigurationId(authResult, eventBuilder));

            OAuth2ErrorRepresentation error =
                    (OAuth2ErrorRepresentation) ex.getResponse().getEntity();
            assertEquals(ErrorType.INVALID_CREDENTIAL_REQUEST.getValue(), error.getError());
            assertTrue(error.getErrorDescription().contains("Multiple authorization_details not supported"));
            verify(eventBuilder).error(ErrorType.INVALID_CREDENTIAL_REQUEST.getValue());
        }
    }

    public static CredentialScopeModel mockedScope(List<PresentationDuringIssuanceMode> modes, String profileId) {
        return new CredentialScopeModel(clientScope(
                Optional.ofNullable(modes)
                        .map(values -> values.stream()
                                .map(v -> v != null ? v.getValue() : null)
                                .collect(Collectors.joining(",")))
                        .orElse(null),
                profileId));
    }

    private static UserSessionModel sessionWithNote(PresentationDuringIssuanceMode mode, String profileId) {
        UserSessionModel session = mock(UserSessionModel.class);
        String note = mode == null
                ? null
                : PresentationVerifiedNote.of(mode, profileId).toJson();
        lenient().when(session.getNote(PRESENTATION_VERIFIED_NOTE)).thenReturn(note);
        return session;
    }

    /**
     * Test double that extends {@link PatchedOID4VCIssuerEndpoint} with a mocked {@link KeycloakSession}.
     */
    static class MockPatchedOID4VCIssuerEndpoint extends PatchedOID4VCIssuerEndpoint {

        static final String TEST_KID = "test-enc-kid";

        MockPatchedOID4VCIssuerEndpoint() {
            super(stubSession("true", null));
        }

        MockPatchedOID4VCIssuerEndpoint(String attributeValue, List<KeyWrapper> encKeys) {
            super(stubSession(attributeValue, encKeys));
        }

        static KeycloakSession stubSession(String attributeValue, List<KeyWrapper> encKeys) {
            KeycloakSessionFactory factory = mock(KeycloakSessionFactory.class);
            lenient()
                    .when(factory.getProviderFactoriesStream(CredentialBuilder.class))
                    .thenReturn(Stream.of());

            RealmModel realm = mock(RealmModel.class);
            lenient().when(realm.getAttribute(ATTR_PATCH_CREDENTIAL_REQUESTS)).thenReturn(attributeValue);

            KeycloakContext context = mock(KeycloakContext.class);
            lenient().when(context.getRealm()).thenReturn(realm);
            lenient().when(context.getConnection()).thenReturn(mock(ClientConnection.class));

            KeycloakSession session = mock(KeycloakSession.class);
            lenient().when(session.getKeycloakSessionFactory()).thenReturn(factory);
            lenient().when(session.getContext()).thenReturn(context);

            if (encKeys != null) {
                KeyManager keyManager = mock(KeyManager.class);
                lenient().when(session.keys()).thenReturn(keyManager);
                lenient().when(keyManager.getKeysStream(realm)).thenAnswer(invocation -> encKeys.stream());
            }

            return session;
        }

        public KeycloakSession getSession() {
            return keycloakSession;
        }

        public EventBuilder getEventBuilder() {
            EventBuilder eventBuilder = mock(EventBuilder.class);
            when(eventBuilder.detail(anyString(), anyString())).thenReturn(eventBuilder);
            return eventBuilder;
        }
    }
}
