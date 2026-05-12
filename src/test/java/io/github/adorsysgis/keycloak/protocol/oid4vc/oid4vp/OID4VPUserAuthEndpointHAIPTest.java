package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.REGISTRATION_CERT_FORMAT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService.SUPPORTED_ENC_ALGS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainerTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.VerifierInfo;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.X509HashUtils;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
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
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

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
        assertEquals(expectedClientId, clientIdParam, "Client ID should use x509_hash scheme");

        // Request object must use configured client ID scheme
        assertEquals(ClientIdScheme.X509_HASH, requestObject.getClientIdScheme());

        // Request object must use configured response mode
        assertEquals(ResponseMode.DIRECT_POST_JWT, requestObject.getResponseMode());

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
    public void shouldAcceptUnencryptedWalletErrorResponse() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        String errorDescription = "Wallet could not encrypt the response";

        HttpResponse response = sendAuthorizationErrorResponse(
                requestObject,
                ProcessingError.INVALID_REQUEST.getErrorString(),
                errorDescription,
                requestObject.getState());
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.ERROR, statusPayload.getStatus());
        assertEquals(ProcessingError.INVALID_REQUEST, statusPayload.getError());
        assertEquals(errorDescription, statusPayload.getErrorDescription());
    }

    private ObjectNode getAuthConfig() {
        ObjectNode json = getTestResourceJson("/realms/test-realm-haip.json");
        ArrayNode config = (ArrayNode) json.get("authenticatorConfig");
        return (ObjectNode) config.get(0).get("config");
    }
}
