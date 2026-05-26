package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.AUTH_REQ_JWT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.REGISTRATION_CERT_FORMAT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService.SUPPORTED_ENC_ALGS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainerTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.VerifierInfo;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.X509HashUtils;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing compliance of the flow with requirements from the German wallet.
 * @see <a href="https://bmi.usercontent.opencode.de/eudi-wallet/wallet-development-documentation-public/latest/architecture-concept/flows/22-pid-presentation">PID Presentation</a>
 */
public class OID4VPUserAuthEndpointHAIPTest extends OID4VPBaseUserAuthEndpointTest {

    public static final String CUSTOM_URL_SCHEME = "haip-vp";

    // For some reasons, you can't have users across realms with the same ID
    public static final String TEST_USER_HAIP = "test-user-haip";

    @Override
    public String getActiveTestRealm() {
        return TEST_REALM_HAIP_NAME;
    }

    @Test
    public void shouldProduceValidAuthorizationRequests() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();
        String signedReqJwt = resolveSignedRequestObject(authRequest);
        JWSInput jwsInput = new JWSInput(signedReqJwt);
        RequestObject requestObject = jwsInput.readJsonContent(RequestObject.class);
        HttpResponse requestUriResponse = resolveSignedRequestObjectResponse(authRequest);
        assertEquals(
                OID4VPUserAuthEndpoint.AUTH_REQ_JWT_MEDIA_TYPE,
                requestUriResponse.getEntity().getContentType().getValue());
        assertEquals(AUTH_REQ_JWT, jwsInput.getHeader().getType());

        // Must use configured custom URL scheme
        URI authRequestUri = new URI(authRequest);
        assertEquals(CUSTOM_URL_SCHEME, authRequestUri.getScheme());

        // Parse query parameters
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(authRequestUri);
        String clientIdParam = uriInfo.getQueryParameters().getFirst("client_id");
        assertNotNull(clientIdParam, "client_id parameter should be present");

        // Assert client ID uses x509_hash appropriately
        ObjectNode authConfig = getAuthConfig();
        String accessCertificate = authConfig.get(ACCESS_CERTIFICATE_CONFIG).asText();
        X509Certificate cert = PemUtils.decodeCertificate(accessCertificate);
        String expectedClientId = "x509_hash:" + X509HashUtils.computeX509Hash(cert);
        assertEquals(expectedClientId, clientIdParam, "Client ID should use x509_hash prefix");

        // Client Identifier Prefix is conveyed through client_id.
        assertEquals(expectedClientId, requestObject.getClientId());
        assertEquals(expectedClientId, requestObject.getIssuer());
        ObjectNode requestPayload = JsonSerialization.readValue(jwsInput.getContent(), ObjectNode.class);
        assertFalse(requestPayload.has("client_id_scheme"), "Signed request object must not contain client_id_scheme");

        // Request object must use configured response mode
        assertEquals(ResponseMode.DIRECT_POST_JWT, requestObject.getResponseMode());
        assertEquals(getVerifierClientId(), new URI(requestObject.getResponseUri()).getHost());

        // Assert: Ensure the request object contains a DCQL query
        var queryMap = new SdJwtCredentialConstrainer.QueryMap(
                List.of(VCT_CONFIG_DEFAULT), List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));
        SdJwtCredentialConstrainerTest.assertDcqlQuery(requestObject.getDcqlQuery(), queryMap);

        // Signed request object must embed access certificate in X5C header
        assertTrue(accessCertificate.startsWith("MIIDITCCAgmgAwIBAgIUcQyt0bvRf7/e4/Gtfw0OHRIBJfU"));
        assertEquals(List.of(accessCertificate), jwsInput.getHeader().getX5c());

        // Request object must advertise registration certificate
        List<VerifierInfo> verifierInfo = requestObject.getVerifierInfo();
        assertEquals(1, verifierInfo.size());
        assertEquals(REGISTRATION_CERT_FORMAT, verifierInfo.getFirst().getFormat());
        assertEquals(
                authConfig.get(REGISTRATION_CERTIFICATE_CONFIG).asText(),
                verifierInfo.getFirst().getData());

        // Request object must advertise an ephemeral key for response encryption
        ClientMetadata clientMetadata = requestObject.getClientMetadata();
        JSONWebKeySet jwks = clientMetadata.getJwks();
        assertEquals(1, jwks.getKeys().length);
        JWK jwk = jwks.getKeys()[0];
        assertNotNull(jwk.getKeyId(), "A key ID is mandatory");
        assertEquals(KeyType.EC, jwk.getKeyType());
        assertEquals(KeyUse.ENC.getSpecName(), jwk.getPublicKeyUse());
        assertEquals(JWEConstants.ECDH_ES, jwk.getAlgorithm());
        assertNull(jwk.getOtherClaims().get(ECTestUtils.JWK_SECRET_D_FIELD));

        // Request object must explicitly advertise support encryption algs
        assertEquals(SUPPORTED_ENC_ALGS, clientMetadata.getEncryptedResponseEncValuesSupported());
    }

    @Test
    public void shouldAuthenticateSuccessfully() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER_HAIP);

        // Proceed to authentication
        var opts = TestOpts.getDefault().setTestUser(TEST_USER_HAIP);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldRejectUnencryptedResponses() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send an OpenID4VP response without encryption
        String vpToken = "sd-jwt-vp-token";
        var opts = TestOpts.getDefault().setShouldForceUnencryptedResponse(true);
        HttpResponse response = sendAuthorizationResponseWithVPToken(vpToken, requestObject, opts);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains("Authorization context expects encrypted response"));
    }

    @Test
    public void shouldAcceptUnencryptedWalletError_WhenEncryptedResponseIsExpected() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        HttpPost httpPost = new HttpPost(requestObject.getResponseUri());
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(
                new BasicNameValuePair(OAuth2Constants.ERROR, OAuthErrorException.ACCESS_DENIED),
                new BasicNameValuePair(OAuth2Constants.ERROR_DESCRIPTION, "wallet canceled presentation"),
                new BasicNameValuePair(ResponseObject.STATE_KEY, authContext.getRequestId()))));

        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        assertEquals(HttpStatus.SC_OK, statusResponse.getStatusLine().getStatusCode());
        AuthorizationContext status = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.ERROR, status.getStatus());
        assertEquals(ProcessingError.WALLET_OAUTH_ERROR, status.getError());
        String description = status.getErrorDescription();
        assertTrue(
                description.contains("Wallet returned error: access_denied")
                        && description.contains("wallet canceled presentation"),
                description);
    }

    @Test
    public void shouldRejectEncryptedResponse_WithUnsupportedAlg() throws Exception {
        assertEncryptedJweRejected(
                JWEConstants.ECDH_ES_A128KW, JWEConstants.A128GCM, null, "Unsupported JWE key management algorithm");
    }

    @Test
    public void shouldRejectEncryptedResponse_WithUnsupportedEnc() throws Exception {
        assertEncryptedJweRejected(
                JWEConstants.ECDH_ES, JWEConstants.A192GCM, null, "Unsupported JWE content encryption algorithm");
    }

    @Test
    public void shouldRejectEncryptedResponse_WithInvalidKid() throws Exception {
        assertEncryptedJweRejected(
                JWEConstants.ECDH_ES,
                JWEConstants.A128GCM,
                "invalid-kid",
                "does not match the encryption key advertised");
    }

    @Test
    public void shouldRejectEncryptedResponse_MalformedJwe() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        HttpPost httpPost = new HttpPost(requestObject.getResponseUri());
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("response", "malformed"))));
        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains("Encrypted response is not a compact JWE"));
    }

    private void assertEncryptedJweRejected(String alg, String enc, String overrideKid, String expectedMessage)
            throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Build minimal encrypted response payload
        var dcql = requestObject.getDcqlQuery();
        String credentialId = dcql.getCredentials().getFirst().getId();
        var vpTokenMap = Map.of(credentialId, List.of("sd-jwt-vp-token"));
        String payload = JsonSerialization.writeValueAsString(Map.of(ResponseObject.VP_TOKEN_KEY, vpTokenMap));

        // Encrypt with requested variations
        JWK encJwk = requestObject.getClientMetadata().getJwks().getKeys()[0];
        var encKey = (ECPublicKey) JWKParser.create(encJwk).toPublicKey();
        String kid = overrideKid == null ? encJwk.getKeyId() : overrideKid;
        String encrypted = ECTestUtils.encryptMessage(payload, encKey, alg, enc, kid);

        // Send OpenID4VP response
        HttpPost httpPost = new HttpPost(requestObject.getResponseUri());
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("response", encrypted))));
        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains(expectedMessage));
    }

    private ObjectNode getAuthConfig() {
        ObjectNode json = getTestResourceJson("/realms/test-realm-haip.json");
        ArrayNode config = (ArrayNode) json.get("authenticatorConfig");
        return (ObjectNode) config.get(0).get("config");
    }
}
