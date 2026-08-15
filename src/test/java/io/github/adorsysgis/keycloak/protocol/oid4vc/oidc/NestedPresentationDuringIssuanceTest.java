package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.constants.OID4VCIConstants.OID4VC_PROTOCOL;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseUserAuthEndpointTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.Map;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.jsoup.Connection;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientScopeRepresentation;

/**
 * End-to-end test for the replacement ("nested OID4VP flow") variant of presentation during
 * issuance: an OIDC authorization request targeting a {@code nested_oid4vp_flow}-gated credential
 * is rendered as a same-device OpenID4VP login view instead of a username/password form, then
 * resumes through {@link OID4VPLoginActionsService} (LoginActions) to hand back a fresh OIDC code.
 */
class NestedPresentationDuringIssuanceTest extends OID4VPBaseUserAuthEndpointTest {

    /** Client-scope (credential configuration) name gated via the nested OID4VP flow. */
    private static final String NESTED_GATED_CONFIG_ID = "nested_gated_credential";

    /** The credential-identity profile (recovers the user from the presented SD-JWT claims). */
    private static final String DEFAULT_PROFILE_ID = "default";

    private final SdJwtVPTestUtils sdJwtVPTestUtils = new SdJwtVPTestUtils(keycloak, getActiveTestRealm());

    @BeforeAll
    static void ensureNestedGatedCredentialScope() {
        var realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        ensureCredentialScope(realm);
    }

    private static void ensureCredentialScope(RealmResource realm) {
        boolean exists =
                realm.clientScopes().findAll().stream().anyMatch(s -> NESTED_GATED_CONFIG_ID.equals(s.getName()));
        if (!exists) {
            ClientScopeRepresentation scope = new ClientScopeRepresentation();
            scope.setName(NESTED_GATED_CONFIG_ID);
            scope.setProtocol(OID4VC_PROTOCOL);
            scope.setAttributes(Map.of(
                    "vc.credential_configuration_id",
                    NESTED_GATED_CONFIG_ID,
                    "vc.verifiable_credential_type",
                    CREDENTIAL_TYPES_CONFIG_DEFAULT.split(",")[0],
                    "vc.format",
                    "dc+sd-jwt",
                    "vc.presentation_profile_id",
                    DEFAULT_PROFILE_ID,
                    "vc.requires_presentation",
                    PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW.getValue()));
            try (var response = realm.clientScopes().create(scope)) {
                int status = response.getStatus();
                if (status != HttpStatus.SC_CREATED && status != HttpStatus.SC_CONFLICT) {
                    throw new IllegalStateException("Failed to create credential scope: HTTP " + status);
                }
            }
        }

        String scopeId = realm.clientScopes().findAll().stream()
                .filter(s -> NESTED_GATED_CONFIG_ID.equals(s.getName()))
                .map(ClientScopeRepresentation::getId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Credential scope not found"));
        var clients = realm.clients().findByClientId(TEST_CLIENT_ID);
        if (clients.isEmpty()) {
            throw new IllegalStateException("Test client not found: " + TEST_CLIENT_ID);
        }
        realm.clients().get(clients.getFirst().getId()).addOptionalClientScope(scopeId);
    }

    @Test
    void shouldReplaceLoginWithPresentation_AndResumeViaLoginActions() throws Exception {
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // OIDC authorization request targeting the nested-flow-gated credential. No login_method,
        // no username/password: the login form must be replaced by an OpenID4VP presentation.
        String authEndpoint = new URIBuilder(getAuthEndpointURI())
                .addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .addParameter(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .addParameter(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI)
                .addParameter(OAuth2Constants.SCOPE, NESTED_GATED_CONFIG_ID)
                .build()
                .toString();

        // Capture the browser session cookies (Jsoup drops the Secure flag so they survive HTTP).
        Connection.Response initial = org.jsoup.Jsoup.connect(authEndpoint)
                .method(Connection.Method.GET)
                .followRedirects(false)
                .ignoreContentType(true)
                .ignoreHttpErrors(true)
                .execute();
        assertEquals(HttpStatus.SC_OK, initial.statusCode());

        String location = initial.parse().select("a").attr("href");
        assertNotNull(location, "Intercepted authorize request must render a same-device link");
        assertFalse(location.isBlank(), "Same-device link must not be empty");
        assertTrue(
                location.startsWith("openid4vp://"),
                "Intercepted authorize request must redirect to an openid4vp:// link, got: " + location);
        assertTrue(
                location.contains("&request_uri=http%3A%2F%2F"),
                "Nested request_uri must remain an encoded HTTP URL inside the openid4vp link: " + location);

        BasicCookieStore cookieStore = convertCookiesMapToStore(initial.cookies());

        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore)
                .disableRedirectHandling()
                .build()) {
            // Complete the same-device OpenID4VP presentation.
            AuthorizationContext authContext = new AuthorizationContext().setAuthorizationRequest(location);
            TestOpts opts = TestOpts.getDefault().setAuthContext(authContext).setShouldRetrieveAccessToken(false);
            TestFlowData flowData = testSuccessfulAuthenticationVerbose(sdJwt, opts);

            // Same-device flow hands back a callback redirect URI.
            ResponseToWallet responseToWallet = flowData.responseToWallet();
            String callbackUri = responseToWallet.getRedirectUri();
            assertNotNull(callbackUri, "Same-device flow should provide a callback redirect URI");

            // The callback resumes the OIDC flow through LoginActions and yields a fresh OIDC code.
            HttpResponse callbackResponse = httpClient.execute(new HttpGet(callbackUri));
            String loginActionUrl = captureNextRedirect(callbackResponse);
            assertTrue(
                    loginActionUrl.contains(OID4VPLoginActionsService.OID4VP_AUTH_LOGIN_PATH),
                    "Flow must resume through the OID4VP LoginActions service, got: " + loginActionUrl);

            String freshAuthCode = extractAuthCodeInRedirect(httpClient.execute(new HttpGet(loginActionUrl)));
            assertNotNull(freshAuthCode, "A fresh OIDC authorization code must be issued");
            assertFalse(freshAuthCode.isBlank());
        }
    }
}
