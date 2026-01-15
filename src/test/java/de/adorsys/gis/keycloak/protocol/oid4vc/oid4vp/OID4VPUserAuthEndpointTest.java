package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp;

import static de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint.REQUEST_JWT_PATH;
import static de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.pruneAuthSessionId;
import static de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
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
import org.apache.http.message.BasicNameValuePair;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing OpenID4VP user authentication via presentation of SD-JWT identity credentials.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointTest extends OID4VPBaseKeycloakTest {

    public static final String VCT_CONFIG_ALT = "https://example.com/vct-alt";

    private final SdJwtVPTestUtils sdJwtVPTestUtils = new SdJwtVPTestUtils(keycloak, getActiveTestRealm());

    @Test
    public void shouldProduceAuthorizationRequests() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();

        // Assert: These fields must be present.
        assertNotNull(authContext.getAuthorizationRequest());
        assertNotNull(authContext.getTransactionId());

        // The authorization request must be a valid URL of scheme "openid4vp".
        URI authRequest = new URI(authContext.getAuthorizationRequest());
        assertEquals("openid4vp", authRequest.getScheme());
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
    public void shouldAuthenticateSuccessfully_UnknownUser() throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication
        String testUser = "unknown-user";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, testUser);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault().setTestUser(testUser));
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

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response =
                sendAuthorizationResponseWithVPToken("sd-jwt-vptoken", requestObject, TestOpts.getDefault());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        // Assert error response
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(
                "Authorization context not found for state (request ID): unknown-session-id",
                errorRep.getErrorDescription());
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
        assertEquals(
                "Unparseable response params (vp_token must not be null or blank)", errorRep.getErrorDescription());
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
    public void shouldFailAuthentication_SdJwtWithNoUsername() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, null);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid SD-JWT presentation (A required field was not presented: `username`)");
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

    /**
     * Helper for successful flows.
     */
    private String testSuccessfulAuthentication(String sdJwt, TestOpts opts) throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Check auth status
        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.SUCCESS, statusPayload.getStatus());

        // Exchange authorization code for access token
        String authCode = statusPayload.getAuthorizationCode();
        assertNotNull(authCode, "Authorization code should not be null");
        if (opts.shouldRetrieveAccessToken()) {
            assertAuthenticatingUser(opts, authCode);
        }

        // Bubble up authorization code
        return authCode;
    }

    private void assertAuthenticatingUser(TestOpts opts, String authCode) throws VerificationException, IOException {
        String accessTokenStr = requestAccessToken(authCode, opts.shouldEnforceRedirectUri());
        AccessToken accessToken =
                TokenVerifier.create(accessTokenStr, AccessToken.class).getToken();

        // Assert authenticating user
        assertEquals(opts.getTestUser(), accessToken.getPreferredUsername());

        // Assert token issuer
        assertEquals(getTestRealmEndpoint(), accessToken.getIssuer());
    }

    /**
     * Helper for failing flows.
     */
    private void testFailingAuthentication(
            String sdJwt, TestOpts opts, int httpStatus, String expectedError, String expectedErrorDescription)
            throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        if (opts.getOverridePresentationDefinitionId() != null) {
            requestObject.getPresentationDefinition().setId(opts.getOverridePresentationDefinitionId());
        }

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);

        // Run assertions
        assertFailingAuthentication(
                response, authContext.getTransactionId(), httpStatus, expectedError, expectedErrorDescription);
    }

    /**
     * Helper for failing flows (from VP token).
     */
    private void testFailingAuthenticationWithVPToken(
            String sdJwtVpToken,
            RequestObject requestObject,
            String transactionId,
            int httpStatus,
            String expectedError,
            String expectedErrorDescription)
            throws Exception {
        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponseWithVPToken(sdJwtVpToken, requestObject, new TestOpts());

        // Run assertions
        assertFailingAuthentication(response, transactionId, httpStatus, expectedError, expectedErrorDescription);
    }

    /**
     * Helper for asserting failing flows.
     */
    private void assertFailingAuthentication(
            HttpResponse postAuthResponse,
            String transactionId,
            int httpStatus,
            String expectedError,
            String expectedErrorDescription)
            throws Exception {
        assertEquals(httpStatus, postAuthResponse.getStatusLine().getStatusCode());
        OAuth2ErrorRepresentation errorRep = parseErrorResponse(postAuthResponse);
        assertEquals(expectedError, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains(expectedErrorDescription));

        // Check and assert auth status
        HttpResponse statusResponse = fetchAuthenticationStatus(transactionId);
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.ERROR, statusPayload.getStatus());
        assertEquals(expectedError, statusPayload.getError().getErrorString());
        assertTrue(statusPayload.getErrorDescription().contains(expectedErrorDescription));
    }

    /**
     * Helper for failing flows (Invalid KB-JWTs).
     */
    private void testFailAuthentication_InvalidKbJwt(
            String overrideNonce, String overrideAud, JWK holderkey, Integer kbJwtLifespanSecs, String errorMessage)
            throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Retrieve an authorization request
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare SD-JWT VP tokens with invalid KB-JWTs
        String sdJwtVpToken = sdJwtVPTestUtils.presentSdJwt(
                sdJwt,
                overrideNonce == null ? requestObject.getNonce() : overrideNonce,
                overrideAud == null ? requestObject.getClientId() : overrideAud,
                holderkey == null ? SdJwtVPTestUtils.getUserJwk() : holderkey,
                kbJwtLifespanSecs == null ? SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS : kbJwtLifespanSecs);

        // Proceed to authentication
        testFailingAuthenticationWithVPToken(
                sdJwtVpToken,
                requestObject,
                authContext.getTransactionId(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                errorMessage);
    }

    /**
     * Sends an OpenID4VP response to Keycloak, producing an SD-JWT verifiable presentation.
     */
    private HttpResponse sendAuthorizationResponse(String sdJwt, RequestObject requestObject, TestOpts opts)
            throws Exception {
        // Prepare a valid SD-JWT verifiable presentation
        String sdJwtVpToken = sdJwtVPTestUtils.presentSdJwt(
                sdJwt,
                requestObject.getNonce(),
                opts.getOverridePresentationAud() == null
                        ? requestObject.getClientId()
                        : opts.getOverridePresentationAud(),
                SdJwtVPTestUtils.getUserJwk());

        // Base64-encode the SD-JWT VP token if requested
        if (opts.getShouldBase64EncodeVpToken()) {
            byte[] bytes = sdJwtVpToken.getBytes(StandardCharsets.UTF_8);
            sdJwtVpToken = Base64.getUrlEncoder().encodeToString(bytes);
        }

        // Send the OpenID4VP response to Keycloak
        return sendAuthorizationResponseWithVPToken(sdJwtVpToken, requestObject, opts);
    }

    /**
     * Sends an OpenID4VP response to Keycloak, producing an SD-JWT verifiable presentation.
     */
    private HttpResponse sendAuthorizationResponseWithVPToken(
            String sdJwtVpToken, RequestObject requestObject, TestOpts opts) throws Exception {
        // Wrap the SD-JWT VP in an OpenID4VP response
        List<BasicNameValuePair> oid4vpResponse = prepareOpenID4VPResponse(sdJwtVpToken, requestObject, opts);

        // Send the OpenID4VP response to Keycloak
        String url = getOid4vpEndpoint("/response");
        HttpPost httpPost = new HttpPost(url);
        httpPost.setEntity(new UrlEncodedFormEntity(oid4vpResponse));
        return httpClient.execute(httpPost);
    }

    /**
     * Prepare the OpenID4VP response object to be sent to Keycloak.
     *
     * @param sdJwtVpToken  the SD-JWT verifiable presentation token
     * @param requestObject the request object containing the presentation definition
     */
    private List<BasicNameValuePair> prepareOpenID4VPResponse(
            String sdJwtVpToken, RequestObject requestObject, TestOpts opts) throws IOException {
        // Build presentation submission

        PresentationDefinition definition = requestObject.getPresentationDefinition();
        InputDescriptor inputDescriptor = definition.getInputDescriptors().getFirst();

        PresentationSubmission submission = new PresentationSubmission();
        submission.setId(UUID.randomUUID().toString());
        submission.setDefinitionId(definition.getId());

        Descriptor descriptor = new Descriptor();
        descriptor.setId(inputDescriptor.getId());
        descriptor.setFormat(
                opts.getOverrideDescriptorFormat() == null
                        ? Descriptor.Format.VC_SD_JWT
                        : opts.getOverrideDescriptorFormat());
        descriptor.setPath(
                opts.getOverrideDescriptorPath() == null
                        ? AuthorizationResponseService.JSON_PATH_ROOT
                        : opts.getOverrideDescriptorPath());
        submission.setDescriptorMap(List.of(descriptor));

        // Compose the response object as form-urlencoded parameters

        return new ArrayList<>(List.of(
                new BasicNameValuePair(ResponseObject.VP_TOKEN_KEY, sdJwtVpToken),
                new BasicNameValuePair(
                        ResponseObject.PRESENTATION_SUBMISSION_KEY, JsonSerialization.writeValueAsString(submission)),
                new BasicNameValuePair(ResponseObject.STATE_KEY, requestObject.getState())));
    }

    @Test
    public void shouldAuthenticateSuccessfully_InOIDCFlow() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Collect OIDC session data
        FormData formData = getFreshOid4vpFormActionUrl();
        String actionURI = formData.actionUrl();
        BasicCookieStore cookieStore = formData.cookieStore();

        // Proceed to authentication
        TestOpts opts = TestOpts.getDefault().setShouldRetrieveAccessToken(false);
        String authCode = testSuccessfulAuthentication(sdJwt, opts);
        BasicNameValuePair codeParam = new BasicNameValuePair(OAuth2Constants.CODE, authCode);

        // Continue OIDC flow with auth code
        try (CloseableHttpClient httpClient =
                HttpClientBuilder.create().setDefaultCookieStore(cookieStore).build()) {
            HttpPost httpPost = new HttpPost(actionURI);
            httpPost.setEntity(new UrlEncodedFormEntity(List.of(codeParam)));
            HttpResponse httpResponse = httpClient.execute(httpPost);
            assertEquals(
                    HttpStatus.SC_MOVED_TEMPORARILY,
                    httpResponse.getStatusLine().getStatusCode());

            String redirectUri =
                    httpResponse.getFirstHeader(HttpHeaders.LOCATION).getValue();
            assertTrue(redirectUri.startsWith(TEST_CLIENT_REDIRECT_URI));

            // Extract the authorization code from the redirect URI
            ResteasyUriInfo uriInfo = new ResteasyUriInfo(URI.create(redirectUri));
            String freshAuthCode = uriInfo.getQueryParameters().getFirst(OAuth2Constants.CODE);

            // Assert the validity of the fresh auth code
            assertAuthenticatingUser(opts.setShouldEnforceRedirectUri(true), freshAuthCode);
            assertNotEquals("New code must be issued", authCode, freshAuthCode);

            // TODO: A login method param must be appended to the redirect URI
            // String loginMethod = uriInfo.getQueryParameters().getFirst(PARAM_LOGIN_METHOD);
            // assertEquals(OID4VP_AUTH_LOGIN_PATH, loginMethod);
        }
    }

    /**
     * POJO for test options.
     */
    static class TestOpts {

        private String testUser = TEST_USER;
        private boolean shouldBase64EncodeVpToken;
        private boolean shouldRetrieveAccessToken = true;
        private boolean shouldEnforceRedirectUri = false;
        private String overridePresentationDefinitionId;
        private String overridePresentationAud;
        private Descriptor.Format overrideDescriptorFormat;
        private String overrideDescriptorPath;

        public static TestOpts getDefault() {
            return new TestOpts();
        }

        public String getTestUser() {
            return testUser;
        }

        public TestOpts setTestUser(String testUser) {
            this.testUser = testUser;
            return this;
        }

        public boolean getShouldBase64EncodeVpToken() {
            return shouldBase64EncodeVpToken;
        }

        public TestOpts setShouldBase64EncodeVpToken(boolean shouldBase64EncodeVpToken) {
            this.shouldBase64EncodeVpToken = shouldBase64EncodeVpToken;
            return this;
        }

        public boolean shouldRetrieveAccessToken() {
            return shouldRetrieveAccessToken;
        }

        public TestOpts setShouldRetrieveAccessToken(boolean retrieveAccessToken) {
            this.shouldRetrieveAccessToken = retrieveAccessToken;
            return this;
        }

        public boolean shouldEnforceRedirectUri() {
            return shouldEnforceRedirectUri;
        }

        public TestOpts setShouldEnforceRedirectUri(boolean shouldEnforceRedirectUri) {
            this.shouldEnforceRedirectUri = shouldEnforceRedirectUri;
            return this;
        }

        public String getOverridePresentationDefinitionId() {
            return overridePresentationDefinitionId;
        }

        public TestOpts setOverridePresentationDefinitionId(String overridePresentationDefinitionId) {
            this.overridePresentationDefinitionId = overridePresentationDefinitionId;
            return this;
        }

        public String getOverridePresentationAud() {
            return overridePresentationAud;
        }

        public TestOpts setOverridePresentationAud(String overridePresentationAud) {
            this.overridePresentationAud = overridePresentationAud;
            return this;
        }

        public Descriptor.Format getOverrideDescriptorFormat() {
            return overrideDescriptorFormat;
        }

        public TestOpts setOverrideDescriptorFormat(Descriptor.Format overrideDescriptorFormat) {
            this.overrideDescriptorFormat = overrideDescriptorFormat;
            return this;
        }

        public String getOverrideDescriptorPath() {
            return overrideDescriptorPath;
        }

        public TestOpts setOverrideDescriptorPath(String overrideDescriptorPath) {
            this.overrideDescriptorPath = overrideDescriptorPath;
            return this;
        }
    }
}
