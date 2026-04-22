package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint.REQUEST_JWT_PATH;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.pruneAuthSessionId;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer.QueryMap;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainerTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIBuilder;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/**
 * Testing OpenID4VP user authentication via presentation of SD-JWT identity credentials.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointTest extends OID4VPBaseUserAuthEndpointTest {

    public static final String VCT_CONFIG_ALT = "https://example.com/vct-alt";

    @Test
    public void shouldProduceAuthorizationRequests() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();

        // Assert: These fields must be present.
        assertNotNull(authContext.getAuthorizationRequest());
        assertNotNull(authContext.getTransactionId());

        // The authorization request must be a valid URL of scheme "openid4vp".
        URI authRequest = new URI(authContext.getAuthorizationRequest());
        assertEquals("openid4vp", authRequest.getScheme());

        // Parse query parameters
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(authRequest);
        String clientIdParam = uriInfo.getQueryParameters().getFirst("client_id");
        assertNotNull(clientIdParam, "client_id parameter should be present");

        // Assert full expected format
        String expectedClientId = "x509_san_dns:" + getVerifierClientId();
        assertEquals(expectedClientId, clientIdParam, "Client ID should be correctly prefixed with scheme");
    }

    @Test
    public void shouldResolveRequestURIs() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();

        // Resolve the request_uri parameter from the authorization request
        RequestObject requestObject = resolveRequestObject(authRequest);

        // Assert: Ensure authentication sessions match
        String expectedSessionId = pruneAuthSessionId(authContext.getTransactionId());
        String actualSessionId = pruneAuthSessionId(requestObject.getState());
        assertEquals(expectedSessionId, actualSessionId);

        // Assert: Ensure the request object contains a legacy presentation definition
        var queryMap = new QueryMap(
                List.of(VCT_CONFIG_DEFAULT, VCT_CONFIG_ALT), List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));
        SdJwtCredentialConstrainerTest.assertPrexQuery(requestObject.getPresentationDefinition(), queryMap);

        // Request object must use expected default client ID scheme
        assertEquals(ClientIdScheme.X509_SAN_DNS, requestObject.getClientIdScheme());

        // Assert: client IDs are schemed across the request object
        String schemedClientId = "x509_san_dns:" + getVerifierClientId();
        assertEquals(schemedClientId, requestObject.getIssuer());
        assertEquals(schemedClientId, requestObject.getClientId());

        // Assert: Request object must not advertise symmetric signing algs
        var dcSdJwt = requestObject.getClientMetadata().getVpFormat().getDcSdJwt();
        for (var algs : List.of(dcSdJwt.getSdJwtAlgValues(), dcSdJwt.getKbJwtAlgValues())) {
            assertFalse(algs.stream().anyMatch(alg -> alg.startsWith("HS")));
        }
    }

    @Test
    public void shouldProduceSpaceFreeSignedJwt_ForLissiWalletCompat() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();

        // Resolve the request_uri parameter from the authorization request
        String signedReqJwt = resolveSignedRequestObject(authRequest);

        // Assert no space in the JWT prior to Base64 encoding
        String[] parts = signedReqJwt.split("\\.");
        assertTrue(parts.length >= 2, "Invalid JWT format");
        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
        assertFalse(headerJson.matches(".*\\s.*"), "No space allowed");
        String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]));
        assertFalse(payloadJson.matches(".*\\s.*"), "No space allowed");
    }

    @Test
    public void shouldAttachX5CwithClientIdAsSAN() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();

        // Resolve the request_uri parameter from the authorization request
        String signedReqJwt = resolveSignedRequestObject(authRequest);
        JWSInput jwsInput = new JWSInput(signedReqJwt);

        // Extract X5C leaf certificate from JWT header
        JWSHeader header = jwsInput.getHeader();
        String certStr = header.getX5c().getFirst();
        byte[] certBytes = Base64.getDecoder().decode(certStr);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));

        // Assert SAN was attached to X5C
        Collection<?> sans = cert.getSubjectAlternativeNames();
        assertNotNull(sans, "Certificate should contain SAN extension");
        assertEquals(1, sans.size(), "Certificate should have one SAN entry");

        // Assert SAN in X5C if of type DNS (2)
        List<?> sanEntry = (List<?>) sans.stream().toList().getFirst();
        assertEquals(2, sanEntry.get(0), "Must be of SAN type DNS");

        // Assert SAN in X5C matches client ID
        assertEquals(getVerifierClientId(), sanEntry.get(1), "DNS SAN must match client ID");
    }

    @Test
    public void shouldNotResolveUnknownRequestURIs() throws Exception {
        String requestUri = getOid4vpEndpoint(REQUEST_JWT_PATH + "/unknown-request-uri");
        HttpGet httpGet = new HttpGet(requestUri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(
                "Authorization context not found for request ID: unknown-request-uri", errorRep.getErrorDescription());
    }

    @Test
    public void shouldEnableStatusPolling() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        String transactionId = authContext.getTransactionId();

        // Poll the status of the authorization context
        HttpResponse response = fetchAuthenticationStatus(transactionId);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Parse response and assert status
        AuthorizationContext statusPayload = parseAuthorizationContext(response);
        assertEquals(AuthorizationContextStatus.PENDING, statusPayload.getStatus());
    }

    @Test
    public void shouldNotDiscloseStatusWithRequestIDs() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        String requestId = requestObject.getState();

        // Poll the status of the authorization context
        HttpResponse response = fetchAuthenticationStatus(requestId);
        assertEquals(
                HttpStatus.SC_NOT_FOUND,
                response.getStatusLine().getStatusCode(),
                "Only transaction IDs should enable polling authorization statuses");
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithoutKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak without explicit kid
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER, false, true);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_Base64EncodedVpToken() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Base64-encoded VP token)
        TestOpts opts = TestOpts.getDefault().setShouldBase64EncodeVpToken(true);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_NewDcSdJwtFormat() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Use 'dc-sd+jwt' in presentation submission descriptor)
        TestOpts opts = TestOpts.getDefault().setOverrideDescriptorFormat(Descriptor.Format.DC_SD_JWT);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_SchemedAud() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Prefix aud with scheme)
        String aud = "x509_san_dns:%s".formatted(getVerifierClientId());
        TestOpts opts = TestOpts.getDefault().setOverridePresentationAud(aud);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_OtherAcceptedVct() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_ALT, TEST_USER);

        // Proceed to authentication (Should pass with other accepted VCT)
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldFailAuthentication_IfInvalidClient() throws Exception {
        URI uri = new URIBuilder(getOid4vpEndpoint("/request"))
                .addParameter("client_id", "unknown-client")
                .build();

        HttpGet httpGet = new HttpGet(uri);
        HttpResponse response = httpClient.execute(httpGet);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_CLIENT, errorRep.getError());
    }

    @Test
    public void shouldFailAuthentication_IfRepeatedAfterSuccess() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Repeat to failure as expected
        response = sendAuthorizationResponse(sdJwt, requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(
                "Authorization context is already closed. Cannot process further responses",
                errorRep.getErrorDescription());
    }

    @Test
    public void shouldFailAuthentication_IfUnknownSessionAssociated() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Associate with an unknown session ID
        requestObject.setState("unknown-session-id");
        requestObject.setResponseUri(getOid4vpEndpoint("/response/unknown-session-id"));

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response =
                sendAuthorizationResponseWithVPToken("sd-jwt-vptoken", requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_NOT_FOUND, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(
                "Authorization context not found for request ID: unknown-session-id", errorRep.getErrorDescription());
    }

    @Test
    public void shouldFailAuthentication_InvalidSdJwtVPToken_Empty() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponseWithVPToken(
                "", // This token is invalid because empty
                requestObject,
                new TestOpts());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription()
                .contains("Unparseable response params (vp_token must not be null or blank)"));
    }

    @Test
    public void shouldFailAuthentication_NonMatchingPresentationDefinitionId() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Use a non-matching presentation definition ID
        TestOpts opts = TestOpts.getDefault().setOverridePresentationDefinitionId("unknown-presentation-definition-id");

        testFailingAuthentication(
                sdJwt,
                opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "Presentation submission does not match the expected presentation definition");
    }

    @Test
    public void shouldFailAuthentication_UnsupportedSubmissionDescriptorPath() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Only the root ($) path is supported
        TestOpts opts = TestOpts.getDefault().setOverrideDescriptorPath("$[0]");

        testFailingAuthentication(
                sdJwt,
                opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "Invalid path in presentation submission descriptor: $[0]");
    }

    @Test
    public void shouldFailAuthentication_UnsupportedSubmissionFormat() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Only VC_SD_JWT is supported
        TestOpts opts = TestOpts.getDefault().setOverrideDescriptorFormat(Descriptor.Format.JWT_VP);

        testFailingAuthentication(
                sdJwt,
                opts,
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_PRESENTATION_SUBMISSION.getErrorString(),
                "SD-JWT VP token expected, but received: jwt_vp");
    }

    @Test
    public void shouldFailAuthentication_InvalidSdJwtVPToken_Unparseable() throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        testFailingAuthenticationWithVPToken(
                "a.b.c", // This token is invalid because unparseable as an SD-JWT VP token
                requestObject,
                authContext.getTransactionId(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "Could not parse `vp_token` as an SD-JWT VP token");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithUnexpectedVct() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential("https://this-vct-is-not-expected.com", TEST_USER);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Pattern matching failed for required field");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithNoSubject() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, null, TEST_USER);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid SD-JWT presentation (A required field was not presented: `sub`)");
    }

    @Test
    public void shouldFailAuthentication_IfUserUnknown() throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication.
        String testSubject = "unknown-user-id";
        String testUsername = "unknown-user";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, testSubject, testUsername);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented SD-JWT is unknown");
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithUsernameFallback() throws Exception {
        // Request SD-JWT credentials with an unknown subject but valid username
        String testSubject = "unknown-user-id";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, testSubject, TEST_USER);

        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithMismatchedUsername() throws Exception {
        // Request SD-JWT credentials from Keycloak with a correct subject but mismatched username
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER_ID, "other-user");

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Username mismatch");
    }

    @Test
    public void shouldFailAuthentication_IfUserDisabled() throws Exception {
        String disabledUser = "disabled-user";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, disabledUser);

        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented SD-JWT is disabled");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithoutStatusClaim() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        // Token status is enforced, but we omit the status claim, causing authentication to fail
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER, false, false);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid SD-JWT presentation (Token status verification failed)");
    }

    @Test
    public void shouldFailAuthentication_SdJwtSignedWithDisabledKey() throws Exception {
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(
                VCT_CONFIG_DEFAULT, TEST_USER, true, true, SdJwtVPTestUtils.getDisabledKeycloakJwk());

        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid Issuer-Signed JWT: Signature could not be verified");
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_SignedWithUnboundedKey() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                null,
                null, // Use expected nonce and aud
                SdJwtVPTestUtils.getStrayJwk(), // Use a stray JWK as holder key
                null, // Use default KB-JWT lifespan
                "Key binding JWT invalid");
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_Expired() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                null,
                null, // Use expected nonce and aud
                null, // Use expected holder key
                -SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS, // Use a negative lifespan to expire the KB-JWT
                "Token has expired");
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_InvalidNonce() throws Exception {
        testFailAuthentication_InvalidKbJwt(
                "invalid-nonce", null, null, null, "claim 'nonce' does not match actual value 'invalid-nonce'");
    }

    @Test
    public void shouldFailAuthentication_InvalidKbJwt_InvalidAud() throws Exception {
        var invalidAuds = List.of(
                "invalid-aud",
                ":" + getVerifierClientId(), // Missing scheme
                "double:scheme:" + getVerifierClientId());

        for (String invalidAud : invalidAuds) {
            testFailAuthentication_InvalidKbJwt(
                    null, invalidAud, null, null, "claim 'aud' does not match actual value");
        }
    }
}
