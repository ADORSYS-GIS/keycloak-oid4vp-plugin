package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerEndpoint.DEFLATE_COMPRESSION;
import static org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProvider.ATTR_REQUEST_ZIP_ALGS;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.PresentationDuringIssuanceBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
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
            // This realm configures a root display object for Issuer Metadata.
            // It also configures oid4vci.omit_encryption_metadata=true.
            return TEST_REALM_V2_NAME;
        }

        @Test
        public void shouldExposeRootDisplayObjectAndOmitEncryptionMetadata() {
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

            assertNull(
                    metadata.getCredentialResponseEncryption(),
                    "credential_response_encryption should be omitted when oid4vci.omit_encryption_metadata is enabled");
            assertNull(
                    metadata.getCredentialRequestEncryption(),
                    "credential_request_encryption should be omitted when oid4vci.omit_encryption_metadata is enabled");

            assertFalse(
                    metadataJson.has("authorization_challenge_endpoint"),
                    "authorization_challenge_endpoint must be omitted when presentation during issuance is disabled");
        }
    }

    @Nested
    class TestUnconfiguredRealm extends OID4VPBaseKeycloakTest {

        @Test
        public void shouldNotExposeRootDisplayObjectButAdvertiseEncryptionMetadataByDefault() {
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

    @Nested
    class TestPruneZipValuesSupportedValues extends PresentationDuringIssuanceBaseTest {

        @Test
        public void shouldOmitZipValuesSupportedWhenNotConfigured() throws Exception {
            var realmAttributes =
                    getActiveTestRealmResource().toRepresentation().getAttributes();
            assertNull(realmAttributes.get(ATTR_REQUEST_ZIP_ALGS));

            CredentialIssuer metadata = retrieveCredentialIssuerMetadata();
            assertNull(
                    metadata.getCredentialRequestEncryption().getZipValuesSupported(),
                    "zip_values_supported must be omitted when oid4vci.request.zip.algorithms is not configured");
            assertNull(
                    metadata.getCredentialResponseEncryption().getZipValuesSupported(),
                    "zip_values_supported must be omitted when oid4vci.request.zip.algorithms is not configured");
        }

        @Test
        public void shouldPruneEmptyZipValuesSupportedForUnsupportedValue() throws Exception {
            withRealmAttributes(Map.of(ATTR_REQUEST_ZIP_ALGS, "false"), () -> {
                CredentialIssuer metadata = retrieveCredentialIssuerMetadata();
                // Keycloak maps any non-DEFLATE value to an empty array, which is invalid per the
                // spec; the plugin must omit it.
                assertNull(
                        metadata.getCredentialRequestEncryption().getZipValuesSupported(),
                        "an unsupported value yields an empty array that must be omitted");
                assertNull(
                        metadata.getCredentialResponseEncryption().getZipValuesSupported(),
                        "an unsupported value yields an empty array that must be omitted");
            });
        }

        @Test
        public void shouldKeepConfiguredZipValuesSupported() throws Exception {
            withRealmAttributes(Map.of(ATTR_REQUEST_ZIP_ALGS, DEFLATE_COMPRESSION), () -> {
                CredentialIssuer metadata = retrieveCredentialIssuerMetadata();
                assertEquals(
                        List.of(DEFLATE_COMPRESSION),
                        metadata.getCredentialRequestEncryption().getZipValuesSupported(),
                        "a supported value must be advertised");
                assertEquals(
                        List.of(DEFLATE_COMPRESSION),
                        metadata.getCredentialResponseEncryption().getZipValuesSupported(),
                        "a supported value must be advertised");
            });
        }

        private CredentialIssuer retrieveCredentialIssuerMetadata() throws Exception {
            JsonNode metadataJson =
                    retrieveCredentialIssuerMetadataJson(httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm());
            return JsonSerialization.mapper.treeToValue(metadataJson, CredentialIssuer.class);
        }
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
