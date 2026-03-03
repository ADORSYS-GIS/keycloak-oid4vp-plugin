package io.github.adorsysgis.keycloak.protocol.oid4vc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.core.type.TypeReference;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.util.JsonSerialization;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Base Keycloak test class for leveraging the TestContainers infrastructure.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@Testcontainers
public abstract class BaseKeycloakTest {

    public static final String TEST_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.5.3";

    public static final String TEST_REALM_NAME = "test";
    public static final String TEST_REALM_V2_NAME = "test-v2";
    public static final String TEST_USER = "test-user@localhost";
    public static final String TEST_CLIENT_ID = "test-app";
    public static final String TEST_CLIENT_SECRET = "password";
    public static final String TEST_CLIENT_REDIRECT_URI = "http://localhost:4200/callback";

    protected static CloseableHttpClient httpClient;

    @Container
    protected static final KeycloakContainer keycloak = createKeycloak();

    private static KeycloakContainer createKeycloak() {
        KeycloakContainer container = new KeycloakContainer(TEST_KEYCLOAK_IMAGE);
        container
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withProviderClassesFrom("target/classes", "target/test-classes")
                .withFeaturesEnabled("oid4vc-vci")
                .withRealmImportFile("/realms/test-realm.json")
                .withRealmImportFile("/realms/test-realm-v2.json")
                .withEnv("KC_LOG_LEVEL", "INFO,io.github.adorsysgis:DEBUG");
        return container;
    }

    @BeforeAll
    public static void setup() {
        CryptoIntegration.init(BaseKeycloakTest.class.getClassLoader());
    }

    @BeforeEach
    public void before() {
        httpClient = HttpClientBuilder.create().build();
    }

    @AfterEach
    public void after() throws IOException {
        httpClient.close();
    }

    protected String getActiveTestRealm() {
        return TEST_REALM_NAME;
    }

    protected String getTestRealmEndpoint() {
        String serverUrl = keycloak.getAuthServerUrl();
        return KeycloakUriBuilder.fromUri(serverUrl)
                .path("/realms/{realm}")
                .build(getActiveTestRealm())
                .toString();
    }

    protected String getTestTokenEndpoint() {
        return KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("/protocol/openid-connect/token")
                .build()
                .toString();
    }

    protected List<NameValuePair> getDefaultHttpParams() {
        return new ArrayList<>(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, TEST_CLIENT_SECRET)));
    }

    /**
     * Exchange an authorization code for an access token at the token endpoint.
     */
    protected String requestAccessToken(String code, boolean enforceRedirectUri) throws IOException {
        // Prepare form parameters for the token request
        var params = getDefaultHttpParams();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        params.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        if (enforceRedirectUri) {
            params.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI));
        }

        // Prepare the request
        HttpPost httpPost = new HttpPost(getTestTokenEndpoint());
        httpPost.setEntity(new UrlEncodedFormEntity(params));

        // Execute the request and process the response
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            Map<String, String> payload = JsonSerialization.readValue(json, new TypeReference<>() {});
            return payload.get(OAuth2Constants.ACCESS_TOKEN);
        }
    }
}
