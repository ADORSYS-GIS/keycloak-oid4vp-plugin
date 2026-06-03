package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import jakarta.ws.rs.core.MediaType;
import java.net.URI;
import java.util.List;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Element;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/**
 * Testing OIDC login via OpenID4VP.
 */
public class OID4VPLoginActionsServiceTest extends OID4VPBaseUserAuthEndpointTest {

    private final SdJwtVPTestUtils sdJwtVPTestUtils = new SdJwtVPTestUtils(keycloak, getActiveTestRealm());

    @BeforeEach
    public void setUp() {
        getActiveTestRealmResource().clearEvents();
    }

    @Test
    public void shouldAuthenticateSuccessfully_InOIDCFlow() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Collect OIDC session data
        FormData formData = getFreshOid4vpFormActionUrl();
        AuthorizationContext authContext = formData.authContext();
        String actionURI = formData.actionUrl();
        BasicCookieStore cookieStore = formData.cookieStore();

        // Proceed to authentication
        TestOpts opts = TestOpts.getDefault()
                .setAuthContext(authContext)
                .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier())
                .setShouldRetrieveAccessToken(false);
        String authCode = testSuccessfulAuthentication(sdJwt, opts);
        BasicNameValuePair codeParam = new BasicNameValuePair(OAuth2Constants.CODE, authCode);

        // Continue OIDC flow with auth code
        try (CloseableHttpClient httpClient =
                HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build()) {
            HttpPost httpPost = new HttpPost(actionURI);
            httpPost.setEntity(new UrlEncodedFormEntity(List.of(codeParam)));

            HttpResponse httpResponse = httpClient.execute(httpPost);
            String freshAuthCode = extractAuthCodeInRedirect(httpResponse);

            // Assert the validity of the fresh auth code
            assertAuthenticatingUser(opts.setShouldEnforceRedirectUri(true), freshAuthCode);
            assertNotEquals("New code must be issued", authCode, freshAuthCode);
        }
    }

    @Test
    public void shouldAuthenticateSuccessfully_InOIDCFlow_SameDeviceFlow() throws Exception {
        // Start same-device OpenID4VP authentication flow to obtain a valid callback URI
        TestFlowDataV2 data = startOid4vpAuthSameDevice();
        BasicCookieStore cookieStore = data.formData().cookieStore();
        ResponseToWallet responseToWallet = data.responseToWallet();

        // Assert that response to wallet contains a redirect URI
        String redirectUri = responseToWallet.getRedirectUri();
        assertNotNull(redirectUri, "Response to wallet should contain a redirect URI");
        assertTrue(
                redirectUri.contains(OID4VPUserAuthEndpoint.CALLBACK_URI_PATH),
                "Redirect URI should be on callback path");

        // Continue OIDC flow by redirecting to callback URI
        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore)
                .disableRedirectHandling()
                .build()) {
            // Follow redirect to callback URI and capture next redirect for form submission
            HttpGet httpGet = new HttpGet(redirectUri);
            HttpResponse response = httpClient.execute(httpGet);
            String redirectActionUri = captureNextRedirect(response);

            // Extract the authorization code from the redirect action URI
            ResteasyUriInfo uriInfo = new ResteasyUriInfo(URI.create(redirectActionUri));
            String authCode = uriInfo.getQueryParameters().getFirst(OAuth2Constants.CODE);

            // Continue OIDC flow with auth code in redirect URI
            HttpGet httpGetAction = new HttpGet(redirectActionUri);
            HttpResponse httpResponse = httpClient.execute(httpGetAction);
            String freshAuthCode = extractAuthCodeInRedirect(httpResponse);

            // Assert the validity of the fresh auth code
            TestOpts opts = TestOpts.getDefault()
                    .setOidcPkceCodeVerifier(data.formData().oidcPkceCodeVerifier())
                    .setShouldEnforceRedirectUri(true);
            assertAuthenticatingUser(opts, freshAuthCode);
            assertNotEquals("New code must be issued", authCode, freshAuthCode);

            // Assert that callback URI can no longer be used at this point
            ResteasyUriInfo uri = new ResteasyUriInfo(URI.create(redirectUri));
            String responseCode = uri.getPathSegments().getLast().getPath();
            shouldFailSameDeviceRedirection(
                    httpClient,
                    redirectUri,
                    HttpStatus.SC_NOT_FOUND,
                    "Authorization context not found for response code: " + responseCode);
        }
    }

    @Test
    public void shouldFailAuthentication_IfNonOid4vpCode() throws Exception {
        // Log in with username/password and grab auth code
        String authCode = getFreshAuthorizationCode();

        // Authentication is expected to fail because this auth code was not issued upon OpenID4VP authentication
        shouldFailAuthenticationWithAltAuthCode(
                authCode, "Authorization code was not issued upon OpenID4VP authentication");
    }

    @Test
    public void shouldNotProvisionOid4vpLogin_WhenOidcAuthorizeWithoutPkce() throws Exception {
        String authEndpoint = buildWrappedOidcAuthorizeRequest(false).uri().toString();

        HttpGet httpGet = new HttpGet(authEndpoint);
        try (CloseableHttpClient client = HttpClientBuilder.create().build()) {
            HttpResponse response = client.execute(httpGet);
            int status = response.getStatusLine().getStatusCode();
            if (status == HttpStatus.SC_OK) {
                String html = EntityUtils.toString(response.getEntity());
                assertNull(
                        Jsoup.parse(html).selectFirst("form#kc-oid4vp-completion-form"),
                        "OpenID4VP QR login must not start without PKCE on the parent OIDC authorize request");
            } else {
                assertTrue(
                        status >= HttpStatus.SC_BAD_REQUEST,
                        "Missing parent PKCE should fail before provisioning the OpenID4VP login UI");
            }
        }
    }

    @Test
    public void shouldRejectApiCodeRedemption_ForWrappedOidcFlow() throws Exception {
        FormData formData = getFreshOid4vpFormActionUrl();
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        TestOpts opts = TestOpts.getDefault()
                .setAuthContext(formData.authContext())
                .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier())
                .setShouldRetrieveAccessToken(false);
        testSuccessfulAuthenticationVerbose(sdJwt, opts);

        String codeVerifier = PkceUtils.generateCodeVerifier();
        HttpResponse redemptionResponse =
                redeemAuthorizationCodeResponse(formData.authContext().getTransactionId(), codeVerifier);
        assertEquals(
                HttpStatus.SC_BAD_REQUEST, redemptionResponse.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(redemptionResponse);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription()
                .contains("Authorization code redemption is not configured for this flow"));
    }

    @Test
    public void shouldFailAuthentication_IfOid4vpCodeNotBoundToOIDCSession() throws Exception {
        // This OpenID4VP authorization context is not tied to any browser OIDC session
        ApiFlowData apiFlow = startApiAuthorizationRequest();
        String authCode = completeOid4vpAuth(apiFlow);
        shouldFailAuthenticationWithAltAuthCode(authCode, "Authorization code was not issued for this OIDC session");
    }

    @Test
    public void shouldFailAuthentication_IfOid4vpCodeBoundToAnotherSession() throws Exception {
        // This OpenID4VP authorization context is tied to another browser OIDC session
        FormData formData = getFreshOid4vpFormActionUrl();
        AuthorizationContext authContext = formData.authContext();

        // Authentication is expected to fail because a new, unrelated OIDC session will be started
        String authCode = completeOid4vpAuth(authContext);
        shouldFailAuthenticationWithAltAuthCode(authCode, "Authorization code was not issued for this OIDC session");

        // Try reusing authCode in original session - expected to fail again because the code must
        // have been invalidated upon first malicious use
        getActiveTestRealmResource().clearEvents();
        shouldFailAuthenticationWithAuthCode(formData, authCode, "Authorization code validation failed");
    }

    @Test
    public void shouldFailRedirection_IfInvalidResponseCode() throws Exception {
        // The callback URI embeds an invalid response code
        String callback = getOid4vpEndpoint(
                String.format("/%s/%s", OID4VPUserAuthEndpoint.CALLBACK_URI_PATH, "invalid-response-code"));

        // Follow callback and expect failure due to invalid response code
        try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
            shouldFailSameDeviceRedirection(
                    httpClient,
                    callback,
                    HttpStatus.SC_NOT_FOUND,
                    "Authorization context not found for response code: invalid-response-code");
        }
    }

    @Test
    public void shouldFailRedirection_IfInvalidSessionCookie() throws Exception {
        // Start same-device OpenID4VP authentication flow to obtain a valid callback URI
        TestFlowDataV2 data = startOid4vpAuthSameDevice();
        String redirectUri = data.responseToWallet().getRedirectUri();

        // Continue OIDC flow by redirecting to callback URI
        // Notice that we are not providing the session cookie, which is expected to cause the redirection to fail due
        // to session mismatch
        try (CloseableHttpClient httpClient =
                HttpClientBuilder.create().disableRedirectHandling().build()) {
            shouldFailSameDeviceRedirection(
                    httpClient,
                    redirectUri,
                    HttpStatus.SC_BAD_REQUEST,
                    "Authentication session does not match cookie-tracked session");
        }
    }

    /**
     * Complete API authentication and return auth code.
     */
    private String completeOid4vpAuth(AuthorizationContext authContext) throws Exception {
        return completeOid4vpAuth(new ApiFlowData(authContext, null));
    }

    /**
     * Complete API authentication and return auth code.
     */
    private String completeOid4vpAuth(ApiFlowData apiFlow) throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        TestOpts opts = TestOpts.getDefault()
                .setAuthContext(apiFlow.authContext())
                .setCodeVerifier(apiFlow.codeVerifier())
                .setShouldRetrieveAccessToken(false);
        return testSuccessfulAuthentication(sdJwt, opts);
    }

    /**
     * Starts an OpenID4VP authentication flow with same-device context.
     */
    private TestFlowDataV2 startOid4vpAuthSameDevice() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Collect OIDC session data (same device flow)
        FormData formData = getFreshOid4vpFormActionUrl();
        AuthorizationContext authContext = formData.authContextSameDevice();

        // Proceed to authentication
        TestOpts opts = TestOpts.getDefault()
                .setAuthContext(authContext)
                .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier());
        TestFlowData testFlowData = testSuccessfulAuthenticationVerbose(sdJwt, opts);
        ResponseToWallet responseToWallet = testFlowData.responseToWallet();

        return new TestFlowDataV2(formData, responseToWallet);
    }

    private void shouldFailAuthenticationWithAltAuthCode(String authCode, String reason) throws Exception {
        // Start new, unrelated OIDC authentication session
        FormData formData = getFreshOid4vpFormActionUrl();
        shouldFailAuthenticationWithAuthCode(formData, authCode, reason);
    }

    private void shouldFailAuthenticationWithAuthCode(FormData formData, String authCode, String reason)
            throws Exception {
        // Collect session data
        String actionURI = formData.actionUrl();
        BasicCookieStore cookieStore = formData.cookieStore();

        // Continue OIDC flow with unrelated auth code
        try (CloseableHttpClient httpClient =
                HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build()) {
            HttpPost httpPost = new HttpPost(actionURI);
            httpPost.setHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
            httpPost.setEntity(
                    new UrlEncodedFormEntity(List.of(new BasicNameValuePair(OAuth2Constants.CODE, authCode))));

            HttpResponse httpResponse = httpClient.execute(httpPost);
            assertEquals(HttpStatus.SC_BAD_REQUEST, httpResponse.getStatusLine().getStatusCode());

            OAuth2ErrorRepresentation errorRep = parseErrorResponse(httpResponse);
            assertEquals("Authorization code not valid", errorRep.getError());

            var events = getActiveTestRealmResource().getEvents().stream()
                    .filter(ev -> ev.getType().equals(EventType.LOGIN_ERROR.toString()))
                    .toList();

            assertEquals(1, events.size());
            assertEquals(reason, events.getFirst().getDetails().get(Details.REASON));
        }
    }

    private void shouldFailSameDeviceRedirection(
            CloseableHttpClient httpClient, String redirectUri, int expectedHttpStatus, String expectedErrorMessage)
            throws Exception {
        HttpGet httpGet = new HttpGet(redirectUri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(expectedHttpStatus, response.getStatusLine().getStatusCode());

        // Parse the error response and assert the error message
        String html = EntityUtils.toString(response.getEntity());
        assertNotNull(html, "Response body should not be null");
        Element error = Jsoup.parse(html).selectFirst("#kc-error-message p");
        assertNotNull(error, "Error message element should be present in response");
        assertEquals(expectedErrorMessage, error.text());
    }

    public record TestFlowDataV2(FormData formData, ResponseToWallet responseToWallet) {}
}
