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
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.protocol.oid4vc.model.CredentialIssuer;
import org.keycloak.protocol.oid4vc.model.DisplayObject;
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

            assertNotNull(
                    metadata.getCredentialResponseEncryption(),
                    "credential_response_encryption should be advertised by default");
            assertNotNull(
                    metadata.getCredentialRequestEncryption(),
                    "credential_request_encryption should be advertised by default");
            assertFalse(
                    metadataJson.has("authorization_challenge_endpoint"),
                    "authorization_challenge_endpoint must be omitted when presentation during issuance is disabled");
        }

        @Test
        public void shouldOmitEncryptionWhenAttributeEnabled() {
            RealmResource realm = getActiveTestRealmResource();
            RealmRepresentation rep = realm.toRepresentation();
            Map<String, String> attributes =
                    new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));
            String original = attributes.get(OID4VCIssuerMetadataProvider.ATTR_OMIT_ENCRYPTION);

            try {
                attributes.put(OID4VCIssuerMetadataProvider.ATTR_OMIT_ENCRYPTION, "true");
                rep.setAttributes(attributes);
                realm.update(rep);

                JsonNode metadataJson = assertDoesNotThrow(() -> retrieveCredentialIssuerMetadataJson(
                        httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm()));
                CredentialIssuer metadata = assertDoesNotThrow(
                        () -> JsonSerialization.mapper.treeToValue(metadataJson, CredentialIssuer.class));

                assertNull(
                        metadata.getCredentialResponseEncryption(),
                        "credential_response_encryption should be omitted when oid4vci.omit_encryption is enabled");
                assertNull(
                        metadata.getCredentialRequestEncryption(),
                        "credential_request_encryption should be omitted when oid4vci.omit_encryption is enabled");
            } finally {
                if (original == null) {
                    attributes.remove(OID4VCIssuerMetadataProvider.ATTR_OMIT_ENCRYPTION);
                } else {
                    attributes.put(OID4VCIssuerMetadataProvider.ATTR_OMIT_ENCRYPTION, original);
                }
                rep.setAttributes(attributes);
                realm.update(rep);
            }
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
            assertNotNull(
                    metadata.getCredentialResponseEncryption(),
                    "credential_response_encryption should be advertised by default");
            assertNotNull(
                    metadata.getCredentialRequestEncryption(),
                    "credential_request_encryption should be advertised by default");
            assertEquals(
                    getTestRealmEndpoint() + "/" + AuthorizationChallengeEndpointFactory.PROVIDER_ID,
                    metadataJson.get("authorization_challenge_endpoint").asText());
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
