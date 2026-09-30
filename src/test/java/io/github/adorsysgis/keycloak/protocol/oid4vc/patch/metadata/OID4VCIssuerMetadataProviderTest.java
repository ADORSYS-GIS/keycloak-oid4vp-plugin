package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.DisplayObject;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;

public class OID4VCIssuerMetadataProviderTest {

    @Nested
    class TestConfiguredRealm extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            // This realm configures a root display object for Issuer Metadata
            return TEST_REALM_V2_NAME;
        }

        @Test
        public void shouldExposeRootDisplayObject() {
            JsonNode metadataJson = assertDoesNotThrow(() -> retrieveCredentialIssuerMetadataJson(
                    httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm()));
            CredentialIssuer metadata = assertDoesNotThrow(
                    () -> JsonSerialization.mapper.treeToValue(metadataJson, CredentialIssuer.class));

            List<DisplayObject> display = metadata.getDisplay();
            assertEquals(2, display.size());

            DisplayObject displayEn = display.stream()
                    .filter(d -> d.getLocale().startsWith("en"))
                    .findFirst()
                    .orElseThrow();

            assertEquals("Example Credential Issuer", displayEn.getName());
            assertEquals("https://example.com/logo.png", displayEn.getLogo().getUri());
            assertEquals("Issuer Logo", displayEn.getLogo().getAltText());

            assertNull(metadata.getCredentialResponseEncryption(), "credential_response_encryption should be omitted");
            assertNull(metadata.getCredentialRequestEncryption(), "credential_request_encryption should be omitted");
            assertFalse(
                    metadataJson.has("authorization_challenge_endpoint"),
                    "authorization_challenge_endpoint must be omitted when presentation during issuance is disabled");
        }
    }

    @Nested
    class TestUnconfiguredRealm extends OID4VPBaseKeycloakTest {

        @Test
        public void shouldNotExposeRootDisplayObject() {
            JsonNode metadataJson = assertDoesNotThrow(() -> retrieveCredentialIssuerMetadataJson(
                    httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm()));
            CredentialIssuer metadata = assertDoesNotThrow(
                    () -> JsonSerialization.mapper.treeToValue(metadataJson, CredentialIssuer.class));
            assertNull(metadata.getDisplay());
            assertNull(metadata.getCredentialResponseEncryption(), "credential_response_encryption should be omitted");
            assertNull(metadata.getCredentialRequestEncryption(), "credential_request_encryption should be omitted");
            assertEquals(
                    getTestRealmEndpoint() + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID,
                    metadataJson.get("authorization_challenge_endpoint").asText());
            assertFalse(metadataJson.has("issuer_info"), "issuer_info must be omitted when not configured");
        }
    }

    @Nested
    class TestIssuerInfoRealm extends OID4VPBaseKeycloakTest {

        private static final String ISSUER_INFO_JSON =
                "[{\"format\": \"registration_cert\", " + "\"data\": \"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJEQSJ9.sig\"}]";

        @Override
        public String getActiveTestRealm() {
            return TEST_REALM_NAME;
        }

        @Test
        public void shouldAdvertiseConfiguredIssuerInfo() throws Exception {
            RealmResource realm = getActiveTestRealmResource();
            RealmRepresentation rep = realm.toRepresentation();
            Map<String, String> attributes =
                    new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));

            try {
                attributes.put(OID4VCIssuerMetadataProvider.ATTR_ISSUER_INFO, ISSUER_INFO_JSON);
                rep.setAttributes(attributes);
                realm.update(rep);

                JsonNode issuerInfo = retrieveCredentialIssuerMetadataJson(
                                httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm())
                        .get("issuer_info");
                assertNotNull(issuerInfo, "issuer_info should be advertised when configured");
                assertEquals(1, issuerInfo.size());
                assertEquals(
                        "registration_cert", issuerInfo.get(0).get("format").asText());
                assertEquals(
                        "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJEQSJ9.sig",
                        issuerInfo.get(0).get("data").asText());
            } finally {
                removeIssuerInfoAttribute(realm, rep, attributes);
            }
        }

        @Test
        public void shouldOmitInvalidIssuerInfo() throws Exception {
            RealmResource realm = getActiveTestRealmResource();
            RealmRepresentation rep = realm.toRepresentation();
            Map<String, String> attributes =
                    new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));

            try {
                for (String invalidValue : List.of("not-valid-json", "[{}]", "[]")) {
                    attributes.put(OID4VCIssuerMetadataProvider.ATTR_ISSUER_INFO, invalidValue);
                    rep.setAttributes(attributes);
                    realm.update(rep);

                    assertFalse(
                            retrieveCredentialIssuerMetadataJson(
                                            httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm())
                                    .has("issuer_info"),
                            "issuer_info must be omitted for invalid value: " + invalidValue);
                }
            } finally {
                removeIssuerInfoAttribute(realm, rep, attributes);
            }
        }

        private void removeIssuerInfoAttribute(
                RealmResource realm, RealmRepresentation rep, Map<String, String> attributes) {
            attributes.remove(OID4VCIssuerMetadataProvider.ATTR_ISSUER_INFO);
            rep.setAttributes(attributes);
            realm.update(rep);
        }
    }

    protected CredentialIssuer retrieveCredentialIssuerMetadata(HttpClient httpClient, String serverUrl, String realm)
            throws Exception {
        return JsonSerialization.mapper.treeToValue(
                retrieveCredentialIssuerMetadataJson(httpClient, serverUrl, realm), CredentialIssuer.class);
    }

    protected JsonNode retrieveCredentialIssuerMetadataJson(HttpClient httpClient, String serverUrl, String realm)
            throws Exception {
        String wellKnownEndpoint = KeycloakUriBuilder.fromUri(serverUrl)
                .path("/.well-known/openid-credential-issuer/realms/{realm}")
                .build(realm)
                .toString();

        HttpGet httpGet = new HttpGet(wellKnownEndpoint);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.mapper.readTree(payload);
    }
}
