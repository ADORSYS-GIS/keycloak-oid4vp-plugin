package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.QRCodeTestUtils;
import jakarta.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

/**
 * Base Keycloak test class with common operations for OpenID4VC scenarios.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public abstract class OID4VPBaseKeycloakTest extends BaseKeycloakTest {

    /**
     * Request a fresh OpenID4VP authorization request from Keycloak.
     * A request is sent to the endpoint for this purpose.
     */
    protected AuthorizationContext requestAuthorizationRequest() {
        return startApiAuthorizationRequest().authContext();
    }

    /**
     * Request a fresh OpenID4VP authorization request from Keycloak together with a client-side verifier.
     */
    protected ApiFlowData startApiAuthorizationRequest() {
        try {
            String codeVerifier = PkceUtils.generateCodeVerifier();
            String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            URI uri = new URIBuilder(getOid4vpEndpoint("/request"))
                    .addParameter("client_id", TEST_CLIENT_ID)
                    .addParameter(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
                    .addParameter(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)
                    .build();

            HttpGet httpGet = new HttpGet(uri);
            HttpResponse response = httpClient.execute(httpGet);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

            return new ApiFlowData(parseAuthorizationContext(response), codeVerifier);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Resolve the request object associated with the authorization request.
     * A request is sent to the request_uri dereferencing endpoint to retrieve the request object.     *
     */
    protected RequestObject resolveRequestObject(String authRequest) throws IOException, JWSInputException {
        String signedRequestJwt = resolveSignedRequestObject(authRequest);
        JWSInput jwsInput = new JWSInput(signedRequestJwt);
        return jwsInput.readJsonContent(RequestObject.class);
    }

    /**
     * Dereference {@code request_uri} and return the signed request object JWT (GET by default, or POST when
     * {@code request_uri_method=post} is present in the authorization request).
     */
    protected String resolveSignedRequestObject(String authRequest) throws IOException {
        return resolveSignedRequestObject(authRequest, null, null);
    }

    /**
     * Dereference via POST when the authorization request advertises {@code request_uri_method=post}, with
     * optional {@code wallet_nonce} / {@code wallet_metadata} (OpenID4VP Final 1.0 §5.10).
     */
    protected String resolveSignedRequestObject(String authRequest, String walletNonce, String walletMetadata)
            throws IOException {
        HttpResponse response = resolveSignedRequestObjectResponse(
                authRequest, walletNonce, walletMetadata, OID4VPUserAuthEndpoint.AUTH_REQ_JWT_MEDIA_TYPE);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
    }

    /** GET fallback to the request URI endpoint (RFC 9101 / Final 1.0 compatibility). */
    protected String resolveSignedRequestObjectWithGet(String authRequest) throws IOException {
        String requestUri = getRequiredQueryParam(authRequest, "request_uri");

        HttpResponse response = httpClient.execute(new HttpGet(requestUri));
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
    }

    protected HttpResponse resolveSignedRequestObjectWithGetResponse(String authRequest) throws IOException {
        String requestUri = getRequiredQueryParam(authRequest, "request_uri");

        return httpClient.execute(new HttpGet(requestUri));
    }

    protected HttpResponse resolveSignedRequestObjectResponse(String authRequest) throws IOException {
        return resolveSignedRequestObjectResponse(
                authRequest, null, null, OID4VPUserAuthEndpoint.AUTH_REQ_JWT_MEDIA_TYPE);
    }

    protected HttpResponse resolveSignedRequestObjectResponse(
            String authRequest, String walletNonce, String walletMetadata, String acceptHeader) throws IOException {
        String requestUri = getRequiredQueryParam(authRequest, "request_uri");
        String requestUriMethod = getQueryParam(authRequest, "request_uri_method");
        if (requestUriMethod == null) {
            requestUriMethod = "get";
        }

        if ("post".equalsIgnoreCase(requestUriMethod)) {
            HttpPost httpPost = new HttpPost(requestUri);
            if (acceptHeader != null) {
                httpPost.setHeader(HttpHeaders.ACCEPT, acceptHeader);
            }
            List<BasicNameValuePair> postParams = new ArrayList<>();
            if (walletNonce != null) {
                postParams.add(new BasicNameValuePair("wallet_nonce", walletNonce));
            }
            if (walletMetadata != null) {
                postParams.add(new BasicNameValuePair("wallet_metadata", walletMetadata));
            }
            if (!postParams.isEmpty()) {
                httpPost.setEntity(new UrlEncodedFormEntity(postParams));
            }
            return httpClient.execute(httpPost);
        }

        return httpClient.execute(new HttpGet(requestUri));
    }

    protected String getQueryParam(String authRequest, String name) {
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(URI.create(authRequest));
        return uriInfo.getQueryParameters().getFirst(name);
    }

    protected String getRequiredQueryParam(String authRequest, String name) {
        String val = getQueryParam(authRequest, name);
        if (val == null) {
            throw new AssertionError("Missing query param: " + name);
        }
        return val;
    }

    /**
     * Fetches the authentication status of an opened session by transaction ID.
     */
    protected HttpResponse fetchAuthenticationStatus(String transactionId) throws IOException {
        String url = UriBuilder.fromUri(getTestRealmEndpoint())
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path("status")
                .path(transactionId)
                .build()
                .toString();
        HttpGet httpGet = new HttpGet(url);
        return httpClient.execute(httpGet);
    }

    /**
     * Redeems an authorization code from a completed API authentication flow.
     */
    protected String redeemAuthorizationCode(String transactionId, String codeVerifier) throws IOException {
        HttpResponse response = redeemAuthorizationCodeResponse(transactionId, codeVerifier);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        AuthorizationContext payload = parseAuthorizationContext(response);
        return payload.getAuthorizationCode();
    }

    /**
     * Calls the authorization code redemption endpoint for API authentication flows.
     */
    protected HttpResponse redeemAuthorizationCodeResponse(String transactionId, String codeVerifier)
            throws IOException {
        String url = getOid4vpEndpoint(OID4VPUserAuthEndpoint.AUTH_CODE_PATH);
        HttpPost httpPost = new HttpPost(url);

        List<BasicNameValuePair> formParams = new ArrayList<>();
        formParams.add(new BasicNameValuePair("transaction_id", transactionId));
        if (codeVerifier != null) {
            formParams.add(new BasicNameValuePair(OAuth2Constants.CODE_VERIFIER, codeVerifier));
        }

        httpPost.setEntity(new UrlEncodedFormEntity(formParams));
        return httpClient.execute(httpPost);
    }

    /**
     * OIDC authorize request used to start wrapped OpenID4VP login tests.
     * {@code oidcPkceCodeVerifier} is only set when the parent authorize URL includes PKCE
     * (needed for token endpoint assertions, not for OpenID4VP subflow protection).
     */
    protected record WrappedOidcAuthorizeRequest(URI uri, String oidcPkceCodeVerifier) {}

    /**
     * Builds an OIDC authorize URL for wrapped OpenID4VP login tests.
     */
    protected WrappedOidcAuthorizeRequest buildWrappedOidcAuthorizeRequest(boolean includePkce) throws Exception {
        URIBuilder builder = new URIBuilder(getAuthEndpointURI())
                .addParameter(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP)
                .addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .addParameter(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .addParameter(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI);

        String codeVerifier = null;
        if (includePkce) {
            codeVerifier = PkceUtils.generateCodeVerifier();
            String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            builder.addParameter(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
                    .addParameter(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256);
        }

        return new WrappedOidcAuthorizeRequest(builder.build(), codeVerifier);
    }

    protected FormData getFreshOid4vpFormActionUrl() throws IOException {
        return getFreshOid4vpFormActionUrl(true);
    }

    protected FormData getFreshOid4vpFormActionUrl(boolean requireCrossDeviceContext) throws IOException {
        String authEndpoint;
        String oidcPkceCodeVerifier;
        try {
            WrappedOidcAuthorizeRequest authorizeRequest = buildWrappedOidcAuthorizeRequest(false);
            authEndpoint = authorizeRequest.uri().toString();
            oidcPkceCodeVerifier = authorizeRequest.oidcPkceCodeVerifier();
        } catch (Exception e) {
            throw new IOException(e);
        }

        Connection.Response res =
                Jsoup.connect(authEndpoint).method(Connection.Method.GET).execute();

        // Parse the response HTML
        Document html = res.parse();

        // Capture cookies for session continuity
        Map<String, String> cookieMap = new HashMap<>(res.cookies());
        BasicCookieStore cookies = convertCookiesMapToStore(cookieMap);

        Element form = html.selectFirst("form#kc-oid4vp-completion-form");
        assertNotNull(form, "Login form should be present in the response");

        String actionUrl = form.attr("action");
        assertFalse(actionUrl.isBlank(), "Login form action URL should not be blank");

        // Collect cross-device polling context from page script (not hidden form fields)
        Element script = html.selectFirst("script:containsData(checkAuthStatus)");
        assertNotNull(script, "OpenID4VP polling script should be present in the response");
        String scriptData = script.data();
        Matcher transactionMatcher =
                Pattern.compile("const transactionId = \"([^\"]+)\"").matcher(scriptData);
        Matcher verifierMatcher =
                Pattern.compile("const codeVerifier = \"([^\"]+)\"").matcher(scriptData);
        assertTrue(transactionMatcher.find(), "OpenID4VP transaction ID should be present in the polling script");
        String transactionId = transactionMatcher.group(1);
        assertFalse(StringUtil.isBlank(transactionId), "OpenID4VP transaction ID should not be blank");
        assertTrue(verifierMatcher.find(), "OpenID4VP code verifier should be present in the polling script");
        String oid4vpCodeVerifier = verifierMatcher.group(1);
        assertFalse(StringUtil.isBlank(oid4vpCodeVerifier), "OpenID4VP code verifier should not be blank");

        AuthorizationContext authContext = null;
        if (requireCrossDeviceContext) {
            Element qrCodeImg = html.selectFirst("img#kc-oid4vp-qrcode");
            assertNotNull(qrCodeImg, "QR Code image should be present in the response");
            String qrCodeDataUrl = qrCodeImg.attr("src");
            assertTrue(StringUtil.isNotBlank(qrCodeDataUrl), "QR Code data URL should not be blank");
            String qrCodeReqLink = QRCodeTestUtils.decodeQrCodeFromDataUrl(qrCodeDataUrl);
            authContext = new AuthorizationContext()
                    .setAuthorizationRequest(qrCodeReqLink)
                    .setTransactionId(transactionId);
        }

        // Collect authorization context details (same-device)

        Element authLinkTag = html.selectFirst("a#kc-oid4vp-link");
        assertNotNull(authLinkTag, "Authentication link should be present in the response");
        String authReqLink = authLinkTag.attr("href");

        AuthorizationContext authContextSameDevice = new AuthorizationContext().setAuthorizationRequest(authReqLink);

        return new FormData(
                authContext, authContextSameDevice, actionUrl, cookies, oidcPkceCodeVerifier, oid4vpCodeVerifier);
    }

    /**
     * Gets an authorization code by logging in with username/password.
     */
    protected String getFreshAuthorizationCode() throws IOException {
        String authEndpoint = Objects.requireNonNull(new URIBuilder(getAuthEndpointURI())
                .addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .addParameter(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .addParameter(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI)
                .toString());

        Connection.Response res =
                Jsoup.connect(authEndpoint).method(Connection.Method.GET).execute();

        // Capture cookies for session continuity
        Map<String, String> cookieMap = new HashMap<>(res.cookies());
        BasicCookieStore cookies = convertCookiesMapToStore(cookieMap);

        // Parse the response HTML
        Document html = res.parse();

        Element form = html.selectFirst("form");
        assertNotNull(form, "Login form should be present in the response");

        String actionUrl = form.attr("action");
        assertFalse(actionUrl.isBlank(), "Login form action URL should not be blank");

        try (CloseableHttpClient httpClient =
                HttpClientBuilder.create().setDefaultCookieStore(cookies).build()) {
            HttpPost httpPost = new HttpPost(actionUrl);
            httpPost.setEntity(new UrlEncodedFormEntity(List.of(
                    new BasicNameValuePair(OAuth2Constants.USERNAME, TEST_USER),
                    new BasicNameValuePair(OAuth2Constants.PASSWORD, TEST_USER_PASSWORD))));

            HttpResponse httpResponse = httpClient.execute(httpPost);
            return extractAuthCodeInRedirect(httpResponse);
        }
    }

    protected URI getAuthEndpointURI() {
        return KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/openid-connect/auth")
                .build();
    }

    protected String getOid4vpEndpoint(String route) {
        return KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path(route)
                .build()
                .toString();
    }

    protected String getVerifierClientId() {
        return keycloak.getHost();
    }

    protected static AuthorizationContext parseAuthorizationContext(HttpResponse response) throws IOException {
        return parseHttpResponse(response, AuthorizationContext.class);
    }

    protected static OAuth2ErrorRepresentation parseErrorResponse(HttpResponse response) throws IOException {
        return parseHttpResponse(response, OAuth2ErrorRepresentation.class);
    }

    protected static <T> T parseHttpResponse(HttpResponse response, Class<T> clazz) throws IOException {
        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.readValue(payload, clazz);
    }

    /**
     * Extracts the authorization code from the redirection response after form submission.
     */
    protected static String extractAuthCodeInRedirect(HttpResponse response) throws IOException {
        String redirectUri = captureNextRedirect(response);
        assertTrue(redirectUri.startsWith(TEST_CLIENT_REDIRECT_URI));

        // Extract the authorization code from the redirect URI
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(URI.create(redirectUri));
        return uriInfo.getQueryParameters().getFirst(OAuth2Constants.CODE);
    }

    /**
     * Extracts the next redirect URI from the response.
     */
    protected static String captureNextRedirect(HttpResponse response) throws IOException {
        assertEquals(HttpStatus.SC_MOVED_TEMPORARILY, response.getStatusLine().getStatusCode());
        return response.getFirstHeader(HttpHeaders.LOCATION).getValue();
    }

    /**
     * Converts a map of cookie name-value pairs into a BasicCookieStore.
     * Useful for bridging cookie management between Jsoup and Apache HttpClient.
     */
    protected static BasicCookieStore convertCookiesMapToStore(Map<String, String> cookiesMap) {
        BasicCookieStore cookieStore = new BasicCookieStore();

        cookiesMap.forEach((name, value) -> {
            BasicClientCookie cookie = new BasicClientCookie(name, value);
            cookie.setDomain("localhost");
            cookie.setPath("/");
            cookieStore.addCookie(cookie);
        });

        return cookieStore;
    }

    protected record FormData(
            AuthorizationContext authContext,
            AuthorizationContext authContextSameDevice,
            String actionUrl,
            BasicCookieStore cookieStore,
            String oidcPkceCodeVerifier,
            String oid4vpCodeVerifier) {}

    protected record ApiFlowData(AuthorizationContext authContext, String codeVerifier) {}
}
