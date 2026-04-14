package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import jakarta.ws.rs.core.MediaType;
import java.util.List;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.events.Details;
import org.keycloak.events.EventType;
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
        TestOpts opts =
                TestOpts.getDefault().setAuthorizationContext(authContext).setShouldRetrieveAccessToken(false);
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
    public void shouldFailAuthentication_IfNonOid4vpCode() throws Exception {
        // Log in with username/password and grab auth code
        String authCode = getFreshAuthorizationCode();

        // Authentication is expected to fail because this auth code was not issued upon OpenID4VP authentication
        shouldFailAuthenticationWithAltAuthCode(
                authCode, "Authorization code was not issued upon OpenID4VP authentication");
    }

    @Test
    public void shouldFailAuthentication_IfOid4vpCodeNotBoundToOIDCSession() throws Exception {
        // This OpenID4VP authorization context is not tied to any browser OIDC session
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authCode = completeOid4vpAuth(authContext);
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

    /**
     * Complete API authentication and return auth code.
     */
    private String completeOid4vpAuth(AuthorizationContext authContext) throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Complete authentication with alternate context
        TestOpts opts =
                TestOpts.getDefault().setAuthorizationContext(authContext).setShouldRetrieveAccessToken(false);
        return testSuccessfulAuthentication(sdJwt, opts);
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
}
