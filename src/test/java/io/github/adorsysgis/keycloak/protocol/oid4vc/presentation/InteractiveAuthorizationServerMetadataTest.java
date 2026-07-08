package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.protocol.oidc.utils.PkceUtils;
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
class InteractiveAuthorizationServerMetadataTest extends OID4VPBaseKeycloakTest {

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
                    getOpenidConfiguration().has("authorization_challenge_endpoint"),
                    "authorization_challenge_endpoint must not be advertised when the feature is disabled");

            // Enabled -> present with the correct URL
            updateAttribute(realm, rep, attributes, "true");
            String expected = getTestRealmEndpoint() + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID;
            assertEquals(
                    expected,
                    getOpenidConfiguration()
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
            HttpResponse response = postChallenge(List.of(
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
            assertTrue(
                    error.getErrorDescription().contains("wallet attestation"),
                    "error should explain that a wallet attestation is required");
        } finally {
            restoreAttribute(
                    realm, rep, attributes, AuthorizationChallengeEndpoint.ATTR_REQUIRE_WALLET_ATTESTATION, original);
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

    private JsonNode getOpenidConfiguration() throws Exception {
        String url = getTestRealmEndpoint() + "/.well-known/openid-configuration";
        HttpResponse response = httpClient.execute(new HttpGet(url));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.mapper.readTree(payload);
    }

    private HttpResponse postChallenge(List<BasicNameValuePair> form) throws Exception {
        String url = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path(AuthorizationChallengeEndpointFactory.PROVIDER_ID)
                .build()
                .toString();
        HttpPost post = new HttpPost(url);
        post.setEntity(new UrlEncodedFormEntity(form));
        return httpClient.execute(post);
    }
}
