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
import org.apache.http.util.EntityUtils;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
}
