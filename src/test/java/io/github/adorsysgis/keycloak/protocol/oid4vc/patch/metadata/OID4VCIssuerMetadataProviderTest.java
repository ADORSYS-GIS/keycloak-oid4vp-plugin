package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest;
import java.nio.charset.StandardCharsets;
import java.util.List;
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
            CredentialIssuer metadata = assertDoesNotThrow(() ->
                    retrieveCredentialIssuerMetadata(httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm()));

            List<DisplayObject> display = metadata.getDisplay();
            assertEquals(2, display.size());

            DisplayObject displayEn = display.stream()
                    .filter(d -> d.getLocale().startsWith("en"))
                    .findFirst()
                    .orElseThrow();

            assertEquals("Example Credential Issuer", displayEn.getName());
            assertEquals("https://example.com/logo.png", displayEn.getLogo().getUri());
            assertEquals("Issuer Logo", displayEn.getLogo().getAltText());
        }
    }

    @Nested
    class TestUnconfiguredRealm extends OID4VPBaseKeycloakTest {

        @Test
        public void shouldNotExposeRootDisplayObject() {
            CredentialIssuer metadata = assertDoesNotThrow(() ->
                    retrieveCredentialIssuerMetadata(httpClient, keycloak.getAuthServerUrl(), getActiveTestRealm()));
            assertNull(metadata.getDisplay());
        }
    }

    protected CredentialIssuer retrieveCredentialIssuerMetadata(HttpClient httpClient, String serverUrl, String realm)
            throws Exception {
        String wellKnownEndpoint = KeycloakUriBuilder.fromUri(serverUrl)
                .path("/.well-known/openid-credential-issuer/realms/{realm}")
                .build(realm)
                .toString();

        HttpGet httpGet = new HttpGet(wellKnownEndpoint);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.readValue(payload, CredentialIssuer.class);
    }
}
