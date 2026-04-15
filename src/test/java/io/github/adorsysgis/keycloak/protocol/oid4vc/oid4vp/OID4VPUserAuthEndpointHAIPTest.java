package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.ACCESS_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.REGISTRATION_CERTIFICATE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.REGISTRATION_CERT_FORMAT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.VerifierInfo;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import java.net.URI;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuthErrorException;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
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
        assertEquals(CUSTOM_URL_SCHEME, new URI(authRequest).getScheme());

        // Request object must use configured response mode
        assertEquals(ResponseMode.DIRECT_POST_JWT, requestObject.getResponseMode());

        // Signed request object must embed access certificate in X5C header
        ObjectNode authConfig = getAuthConfig();
        String accessCertificate = authConfig.get(ACCESS_CERTIFICATE_CONFIG).asText();
        assertTrue(accessCertificate.startsWith("MIIB2DCCAX6gAwIBAgIVAJ/cbtVmxliKj42QvoeUp"));
        assertEquals(List.of(accessCertificate), jwsInput.getHeader().getX5c());

        // Request object must advertise registration certificate
        List<VerifierInfo> verifierInfo = requestObject.getVerifierInfo();
        assertEquals(1, verifierInfo.size());
        assertEquals(REGISTRATION_CERT_FORMAT, verifierInfo.getFirst().getFormat());
        assertEquals(
                authConfig.get(REGISTRATION_CERTIFICATE_CONFIG).asText(),
                verifierInfo.getFirst().getData());

        // Request object must advertise an ephemeral key for response encryption
        JSONWebKeySet jwks = requestObject.getClientMetadata().getJwks();
        assertEquals(1, jwks.getKeys().length);
        JWK jwk = jwks.getKeys()[0];
        assertNotNull(jwk.getKeyId(), "A key ID is mandatory");
        assertEquals(KeyType.EC, jwk.getKeyType());
        assertEquals(KeyUse.ENC.getSpecName(), jwk.getPublicKeyUse());
        assertNull(jwk.getOtherClaims().get(ECTestUtils.JWK_SECRET_D_FIELD));
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

    private ObjectNode getAuthConfig() {
        ObjectNode json = getTestResourceJson("/realms/test-realm-haip.json");
        ArrayNode config = (ArrayNode) json.get("authenticatorConfig");
        return (ObjectNode) config.get(0).get("config");
    }
}
