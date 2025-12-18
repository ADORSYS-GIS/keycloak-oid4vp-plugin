package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp;

import de.adorsys.gis.keycloak.protocol.oid4vc.BaseKeycloakTest;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.util.EntityUtils;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static de.adorsys.gis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static de.adorsys.gis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
    protected AuthorizationContext requestAuthorizationRequest() throws Exception {
        URI uri = new URIBuilder(getOid4vpEndpoint("/request"))
                .addParameter("client_id", TEST_CLIENT_ID)
                .build();

        HttpGet httpGet = new HttpGet(uri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        return parseAuthorizationContext(response);
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
     * Resolve the request object associated with the authorization request.
     * A request is sent to the request_uri dereferencing endpoint to retrieve the request object.     *
     */
    protected String resolveSignedRequestObject(String authRequest) throws IOException {
        // Extract the request_uri parameter
        String requestUri = URLEncodedUtils.parse(authRequest, StandardCharsets.UTF_8).stream()
                .filter(p -> p.getName().equals("request_uri"))
                .map(NameValuePair::getValue)
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing query param: request_uri"));

        // Send resolution request
        HttpGet httpGet = new HttpGet(requestUri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Parse and return the expected JWT response
        return EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
    }

    /**
     * Fetches the authentication status of an opened session by transaction ID.
     */
    protected HttpResponse fetchAuthenticationStatus(String transactionId) throws IOException {
        String url = getOid4vpEndpoint(String.format("/status/%s", transactionId));
        HttpGet httpGet = new HttpGet(url);
        return httpClient.execute(httpGet);
    }

    /**
     * Scrapes the action URL of the OpenID4VP login form.
     */
    protected FormData getFreshOid4vpFormActionUrl() throws IOException {
        URI authEndpointUri = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/openid-connect/auth")
                .build();

        String authEndpoint = new URIBuilder(authEndpointUri)
                .addParameter(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP)
                .addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .addParameter(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE)
                .addParameter(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI)
                .toString();

        Connection.Response res = Jsoup.connect(authEndpoint)
                .method(Connection.Method.GET)
                .execute();

        // Parse the response HTML
        Document html = res.parse();

        // Capture cookies for session continuity
        Map<String, String> cookieMap = new HashMap<>(res.cookies());
        BasicCookieStore cookies = convertCookiesMapToStore(cookieMap);

        Element form = html.selectFirst("form#kc-oid4vp-completion-form");
        assertNotNull(form, "Login form should be present in the response");

        String actionUrl = form.attr("action");
        assertFalse(actionUrl.isBlank(), "Login form action URL should not be blank");

        String[] actionUrlParts = actionUrl.split("\\?");
        assertEquals(2, actionUrlParts.length);

        String serverUrl = keycloak.getAuthServerUrl();
        String absActionUrl = String.format("%s?%s",
                KeycloakUriBuilder
                        .fromUri(serverUrl)
                        .path(actionUrlParts[0])
                        .build(),
                actionUrlParts[1]
        );

        return new FormData(absActionUrl, cookies);
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
        return JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                AuthorizationContext.class
        );
    }

    protected static OAuth2ErrorRepresentation parseErrorResponse(HttpResponse response) throws IOException {
        return JsonSerialization.readValue(
                EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8),
                OAuth2ErrorRepresentation.class
        );
    }

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

    protected record FormData(String actionUrl, BasicCookieStore cookieStore) {
    }
}
