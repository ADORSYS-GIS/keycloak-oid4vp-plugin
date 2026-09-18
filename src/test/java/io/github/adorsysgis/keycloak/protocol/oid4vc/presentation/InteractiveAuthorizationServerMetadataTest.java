package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.PresentationDuringIssuanceBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.authentication.authenticators.client.AttestationBasedClientAuthenticator;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * End-to-end tests closing two OID4VCI §6 Interactive Authorization conformance gaps:
 *
 * <ol>
 *   <li>the {@code authorization_challenge_endpoint} is advertised in the <strong>Authorization Server
 *       Metadata</strong> (OIDC {@code .well-known/openid-configuration}) when presentation during
 *       issuance is enabled, and
 *   <li>a required <strong>Wallet Attestation</strong> is enforced on the Authorization Challenge
 *       Request (OID4VCI §6.1, Note; a missing attestation is rejected with
 *       {@code invalid_client_attestation}).
 * </ol>
 */
class InteractiveAuthorizationServerMetadataTest extends PresentationDuringIssuanceBaseTest {

    private static final String IDENTITY_CREDENTIAL_CONFIG_ID = "identity_credential";

    @BeforeAll
    static void ensureIdentityCredentialScope() {
        var realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        assertPresentationDuringIssuanceEnabled(realm);
        ensureCredentialScope(
                realm,
                IDENTITY_CREDENTIAL_CONFIG_ID,
                OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT,
                PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION,
                AuthenticationProfile.DEFAULT_PROFILE_ID);
    }

    @Test
    @DisplayName(
            "authorization_challenge_endpoint is exposed in AS metadata only when presentation during issuance is enabled")
    void authorizationChallengeEndpointInAsMetadata() throws Exception {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(getActiveTestRealm());
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> attributes =
                new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));
        String original = attributes.get(OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE);

        try {
            // Disabled -> absent
            updateAttribute(realm, rep, attributes, "false");
            assertFalse(
                    getAuthorizationServerConfiguration().has("authorization_challenge_endpoint"),
                    "authorization_challenge_endpoint must not be advertised when the feature is disabled");
            assertEquals(
                    HttpStatus.SC_NOT_FOUND,
                    postAuthorizationChallenge(List.of()).getStatusLine().getStatusCode(),
                    "authorization_challenge_endpoint must not respond when the feature is disabled");

            // Enabled -> present with the correct URL
            updateAttribute(realm, rep, attributes, "true");
            String expected = getTestRealmEndpoint() + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
            assertEquals(
                    expected,
                    getAuthorizationServerConfiguration()
                            .get("authorization_challenge_endpoint")
                            .asText());
        } finally {
            restoreAttribute(
                    realm, rep, attributes, OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE, original);
        }
    }

    @Test
    @DisplayName(
            "a required wallet attestation is enforced: a missing attestation is rejected with invalid_client_attestation")
    void requiredWalletAttestationIsEnforced() throws Exception {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(getActiveTestRealm());
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> attributes =
                new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));
        String original = attributes.get(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION);

        try {
            attributes.put(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION, "true");
            rep.setAttributes(attributes);
            realm.update(rep);

            var codeVerifier = PkceUtils.generateCodeVerifier();
            var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

            // Valid interaction type, but no OAuth-Client-Attestation headers -> rejected.
            HttpResponse response = postAuthorizationChallenge(List.of(
                    new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                    new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                    new BasicNameValuePair(
                            AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                            AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                    new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                    new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
            OAuth2ErrorRepresentation error = parseHttpResponse(response, OAuth2ErrorRepresentation.class);
            assertEquals(OAuthErrorException.INVALID_CLIENT_ATTESTATION, error.getError());
            assertEquals("Wallet attestation authentication failed", error.getErrorDescription());
        } finally {
            restoreAttribute(
                    realm, rep, attributes, AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION, original);
        }
    }

    @Test
    @DisplayName("wallet attestation validation runs Keycloak's attestation authenticator directly")
    void walletAttestationValidationUsesKeycloakAuthenticator() throws Exception {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(getActiveTestRealm());
        RealmRepresentation realmRepresentation = realm.toRepresentation();
        Map<String, String> attributes = new HashMap<>(
                Optional.ofNullable(realmRepresentation.getAttributes()).orElseGet(Map::of));
        String originalRequirement = attributes.get(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION);

        try {
            attributes.put(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION, "true");
            realmRepresentation.setAttributes(attributes);
            realm.update(realmRepresentation);

            var codeVerifier = PkceUtils.generateCodeVerifier();
            var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            HttpResponse response = postAuthorizationChallengeWithAttestation(List.of(
                    new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                    new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                    new BasicNameValuePair(
                            AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                            AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                    new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                    new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
            OAuth2ErrorRepresentation error = parseHttpResponse(response, OAuth2ErrorRepresentation.class);
            assertEquals(OAuthErrorException.INVALID_CLIENT_ATTESTATION, error.getError());
            assertEquals(
                    "The JWS type MUST be oauth-client-attestation+jwt instead of not-attestation",
                    error.getErrorDescription());
        } finally {
            restoreAttribute(
                    realm,
                    realmRepresentation,
                    attributes,
                    AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION,
                    originalRequirement);
        }
    }

    @Test
    @DisplayName("a valid wallet attestation passes Keycloak's attestation authenticator")
    void validWalletAttestationPassesKeycloakAuthenticator() throws Exception {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(getActiveTestRealm());
        RealmRepresentation realmRepresentation = realm.toRepresentation();
        Map<String, String> realmAttributes = new HashMap<>(
                Optional.ofNullable(realmRepresentation.getAttributes()).orElseGet(Map::of));
        String originalRequirement =
                realmAttributes.get(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION);
        var clientResource = realm.clients().findByClientId(TEST_CLIENT_ID).stream()
                .findFirst()
                .map(client -> realm.clients().get(client.getId()))
                .orElseThrow();
        ClientRepresentation client = clientResource.toRepresentation();
        Map<String, String> originalAttributes =
                new HashMap<>(Optional.ofNullable(client.getAttributes()).orElseGet(Map::of));
        String trustAlias = "test-attester-trust";

        removeIdentityProvider(realm, trustAlias);
        createTrustProvider(realm, trustAlias);
        try {
            realmAttributes.put(AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION, "true");
            realmRepresentation.setAttributes(realmAttributes);
            realm.update(realmRepresentation);

            Map<String, String> attributes = new HashMap<>(originalAttributes);
            attributes.put(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_CONFIG_TRUST_IDPS, trustAlias);
            client.setAttributes(attributes);
            clientResource.update(client);

            var codeVerifier = PkceUtils.generateCodeVerifier();
            var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            HttpResponse response = postAuthorizationChallengeWithAttestation(
                    List.of(
                            new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                            new BasicNameValuePair(OAuth2Constants.SCOPE, IDENTITY_CREDENTIAL_CONFIG_ID),
                            new BasicNameValuePair(
                                    AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                                    AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                            new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                            new BasicNameValuePair(
                                    OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)),
                    createClientAttestation(),
                    createClientAttestationPop());

            assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusLine().getStatusCode());
            AuthorizationChallengeResponse challenge =
                    parseHttpResponse(response, AuthorizationChallengeResponse.class);
            assertEquals(AuthorizationChallengeEndpoint.ERROR_INSUFFICIENT_AUTHORIZATION, challenge.getError());
            assertNotNull(challenge.getAuthSession());
            assertNotNull(challenge.getOpenid4vpRequest());
        } finally {
            client.setAttributes(originalAttributes);
            clientResource.update(client);
            realm.identityProviders().get(trustAlias).remove();
            restoreAttribute(
                    realm,
                    realmRepresentation,
                    realmAttributes,
                    AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION,
                    originalRequirement);
        }
    }

    private void updateAttribute(
            RealmResource realm, RealmRepresentation rep, Map<String, String> attributes, String value) {
        attributes.put(OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE, value);
        rep.setAttributes(attributes);
        realm.update(rep);
    }

    private void restoreAttribute(
            RealmResource realm, RealmRepresentation rep, Map<String, String> attributes, String key, String original) {
        if (original == null) {
            attributes.remove(key);
        } else {
            attributes.put(key, original);
        }
        rep.setAttributes(attributes);
        realm.update(rep);
    }

    private JsonNode getAuthorizationServerConfiguration() throws Exception {
        String url = getTestRealmEndpoint() + "/.well-known/oauth-authorization-server";
        HttpResponse response = httpClient.execute(new HttpGet(url));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.mapper.readTree(payload);
    }

    private HttpResponse postAuthorizationChallengeWithAttestation(List<BasicNameValuePair> form) throws IOException {
        return postAuthorizationChallengeWithAttestation(
                form, "eyJ0eXAiOiJub3QtYXR0ZXN0YXRpb24ifQ.eA.eA", "eyJ0eXAiOiJub3QtYXR0ZXN0YXRpb24ifQ.eA.eA");
    }

    private HttpResponse postAuthorizationChallengeWithAttestation(
            List<BasicNameValuePair> form, String attestation, String attestationPop) throws IOException {
        String url = getTestRealmEndpoint() + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
        HttpPost post = new HttpPost(url);
        post.setEntity(new UrlEncodedFormEntity(form));
        post.setHeader(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_HEADER, attestation);
        post.setHeader(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_HEADER, attestationPop);
        return httpClient.execute(post);
    }

    private void createTrustProvider(RealmResource realm, String alias) throws Exception {
        JWK attesterJwk = SdJwtVPTestUtils.getKeycloakJwk();
        JWK attesterPublicJwk = RSATestUtils.getRsaPublicJwk(SdJwtVPTestUtils.getKeycloakJwk());
        attesterPublicJwk.setKeyId(attesterJwk.getKeyId());

        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[] {attesterPublicJwk});

        IdentityProviderRepresentation provider = new IdentityProviderRepresentation();
        provider.setAlias(alias);
        provider.setProviderId("default-trust");
        provider.setEnabled(true);
        provider.setConfig(new HashMap<>(Map.of(
                "useJwksUrl",
                "false",
                "publicKeySignatureVerifier",
                JsonSerialization.mapper.writeValueAsString(jwks))));

        try (var response = realm.identityProviders().create(provider)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatus());
        }
    }

    private void removeIdentityProvider(RealmResource realm, String alias) {
        realm.identityProviders().findAll().stream()
                .filter(provider -> alias.equals(provider.getAlias()))
                .findFirst()
                .ifPresent(provider ->
                        realm.identityProviders().get(provider.getAlias()).remove());
    }

    private String createClientAttestation() throws Exception {
        JWK attesterJwk = SdJwtVPTestUtils.getKeycloakJwk();
        var attestation = new AttestationBasedClientAuthenticator.ClientAttestationJwt()
                .issuer("test-attester")
                .subject(TEST_CLIENT_ID)
                .issuedNowWithTTL(60)
                .confirmation(ECTestUtils.getECPublicJwk(SdJwtVPTestUtils.getUserJwk()));

        return new JWSBuilder()
                .type(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_JWT_TYPE)
                .kid(attesterJwk.getKeyId())
                .jsonContent(attestation)
                .sign(new AsymmetricSignatureSignerContext(RSATestUtils.getRsaKeyWrapper(attesterJwk)));
    }

    private String createClientAttestationPop() throws Exception {
        var pop = new org.keycloak.representations.JsonWebToken()
                .issuer(TEST_CLIENT_ID)
                .audience(getTestRealmEndpoint())
                .issuedNowWithTTL(60)
                .id(UUID.randomUUID().toString());

        return new JWSBuilder()
                .type(AttestationBasedClientAuthenticator.OAUTH_CLIENT_ATTESTATION_POP_JWT_TYPE)
                .jsonContent(pop)
                .sign(new ECDSASignatureSignerContext(ECTestUtils.getEcKeyWrapper(SdJwtVPTestUtils.getUserJwk())));
    }
}
