package io.github.adorsysgis.keycloak.protocol.oid4vc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.presentation.AuthorizationChallengeEndpointFactory;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.HttpResponse;
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
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.util.JsonSerialization;

/**
 * Base Keycloak test class for leveraging the TestContainers infrastructure.
 *
 * <p>The Keycloak container is a JVM-wide <strong>singleton</strong>: it is started once (lazily, on
 * first class load) and reused across all test classes in the same Surefire fork, instead of being
 * restarted per test class. It is never stopped explicitly; the Testcontainers Ryuk reaper tears it
 * down at JVM shutdown. This drastically reduces the total test time (one Quarkus augmentation +
 * bootstrap instead of one per test class).
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public abstract class BaseKeycloakTest {

    public static final String TEST_REALM_NAME = "test";
    public static final String TEST_REALM_HAIP_NAME = "test-haip";
    public static final String TEST_REALM_V2_NAME = "test-v2";
    public static final String TEST_REALM_LEGACY_V1_2_6_NAME = "test-legacy-v1-2-6";

    public static final String TEST_USER = "test-user";
    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_USER_PASSWORD = "password";
    public static final String TEST_CLIENT_ID = "test-app";
    public static final String TEST_CLIENT_SECRET = "password";
    public static final String TEST_CLIENT_REDIRECT_URI = "http://localhost:4200/callback";

    protected static CloseableHttpClient httpClient;

    protected static final KeycloakContainer keycloak = createKeycloak();

    static {
        keycloak.start();
    }

    private static KeycloakContainer createKeycloak() {
        return KeycloakTestContainer.create(List.of(
                "/realms/test-realm.json",
                "/realms/test-realm-haip.json",
                "/realms/test-realm-v2.json",
                "/realms/test-realm-legacy-v1-2-6.json"));
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

    protected RealmResource getActiveTestRealmResource() {
        return keycloak.getKeycloakAdminClient().realm(getActiveTestRealm());
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

    protected ObjectNode getTestResourceJson(String filename) {
        try (InputStream stream = BaseKeycloakTest.class.getResourceAsStream(filename)) {
            return (ObjectNode) JsonSerialization.mapper.readTree(stream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    protected List<NameValuePair> getDefaultHttpParams() {
        ArrayList<NameValuePair> params = new ArrayList<>();
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID));
        params.add(new BasicNameValuePair(OAuth2Constants.CLIENT_SECRET, TEST_CLIENT_SECRET));
        return params;
    }

    /**
     * Exchange an authorization code for an access token at the token endpoint.
     */
    protected String requestAccessToken(String code, boolean enforceRedirectUri) throws IOException {
        return requestAccessToken(code, enforceRedirectUri, null);
    }

    protected String requestAccessToken(String code, boolean enforceRedirectUri, String codeVerifier)
            throws IOException {
        // Prepare form parameters for the token request
        var params = getDefaultHttpParams();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE));
        params.add(new BasicNameValuePair(OAuth2Constants.CODE, code));
        if (enforceRedirectUri) {
            params.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI));
        }
        if (codeVerifier != null) {
            params.add(new BasicNameValuePair(OAuth2Constants.CODE_VERIFIER, codeVerifier));
        }

        return requestAccessToken(params);
    }

    /** Executes a token request with the supplied OAuth grant parameters. */
    protected String requestAccessToken(List<? extends NameValuePair> params) throws IOException {
        HttpPost httpPost = new HttpPost(getTestTokenEndpoint());
        httpPost.setEntity(new UrlEncodedFormEntity(params));

        // Execute the request and process the response
        try (CloseableHttpResponse response = httpClient.execute(httpPost)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            JsonNode payload = JsonSerialization.readValue(json, JsonNode.class);
            String accessToken = payload.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
            if (accessToken == null) {
                throw new IllegalStateException("Token response does not contain an access token");
            }
            return accessToken;
        }
    }

    /** Posts a form to the OID4VCI Authorization Challenge Endpoint. */
    protected HttpResponse postAuthorizationChallenge(List<? extends NameValuePair> form) throws IOException {
        String url = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path(AuthorizationChallengeEndpointFactory.PROVIDER_ID)
                .build()
                .toString();
        HttpPost post = new HttpPost(url);
        post.setEntity(new UrlEncodedFormEntity(form));
        return httpClient.execute(post);
    }
}
