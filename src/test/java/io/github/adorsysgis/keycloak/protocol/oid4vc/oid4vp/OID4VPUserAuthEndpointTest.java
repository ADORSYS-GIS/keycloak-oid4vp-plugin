package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint.REQUEST_JWT_PATH;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.pruneAuthSessionId;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer.QueryMap;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.AUTH_REQ_JWT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainerTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing OpenID4VP user authentication via presentation of SD-JWT identity credentials.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthEndpointTest extends OID4VPBaseUserAuthEndpointTest {

    public static final String VCT_CONFIG_ALT = "https://example.com/vct-alt";
    public static final String DUAL_PROFILE_ID = "dual";
    // Imported realm fixture ID for the SD-JWT authenticator config used by these integration tests.
    private static final String TEST_REALM_SD_JWT_AUTH_CONFIG_ID = "81d62be9-cf06-4718-8837-fdfb4727b20a";

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
        assertNull(uriInfo.getQueryParameters().getFirst("request_uri_method"));

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
        String signedReqJwt = resolveSignedRequestObject(authRequest);
        JWSInput jwsInput = new JWSInput(signedReqJwt);
        HttpResponse requestUriResponse = resolveSignedRequestObjectResponse(authRequest);
        assertEquals(
                OID4VPUserAuthEndpoint.AUTH_REQ_JWT_MEDIA_TYPE,
                requestUriResponse.getEntity().getContentType().getValue());

        // Assert: Ensure authentication sessions match
        String expectedSessionId = pruneAuthSessionId(authContext.getTransactionId());
        String actualSessionId = pruneAuthSessionId(requestObject.getState());
        assertEquals(expectedSessionId, actualSessionId);

        // Assert: Ensure the request object contains a final-spec DCQL query.
        var queryMap = new QueryMap(
                List.of(VCT_CONFIG_DEFAULT, VCT_CONFIG_ALT), List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));
        SdJwtCredentialConstrainerTest.assertDcqlQuery(requestObject.getDcqlQuery(), queryMap);

        // Client Identifier Prefix is conveyed through client_id.
        String schemedClientId = "x509_san_dns:" + getVerifierClientId();
        assertEquals(schemedClientId, requestObject.getIssuer());
        assertEquals(schemedClientId, requestObject.getClientId());
        ObjectNode requestPayload = JsonSerialization.readValue(jwsInput.getContent(), ObjectNode.class);
        assertFalse(requestPayload.has("client_id_scheme"), "Signed request object must not contain client_id_scheme");
        assertEquals(getVerifierClientId(), new URI(requestObject.getResponseUri()).getHost());
        assertEquals(ResponseMode.DIRECT_POST, requestObject.getResponseMode());
        assertEquals(AUTH_REQ_JWT, jwsInput.getHeader().getType());

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
        assertNotNull(sanEntry, "SAN entry should not be null");
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
    public void shouldRejectRequestUriPost_WhenMethodIsNotPost() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();
        String authRequest = authContext.getAuthorizationRequest();
        String requestUri = getRequiredQueryParam(authRequest, "request_uri");

        HttpPost httpPost = new HttpPost(requestUri);
        httpPost.setHeader(HttpHeaders.ACCEPT, OID4VPUserAuthEndpoint.AUTH_REQ_JWT_MEDIA_TYPE);
        httpPost.setEntity(new UrlEncodedFormEntity(List.of(new BasicNameValuePair("wallet_nonce", "nonce"))));
        HttpResponse response = httpClient.execute(httpPost);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals("invalid_request_uri_method", errorRep.getError());
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
    public void shouldRejectAuthorizationCodeRedemptionWithMissingVerifier() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Start a valid API authorization flow which generates a code_challenge.
        ApiFlowData apiFlow = startApiAuthorizationRequest();

        // This test will fail because the server enforces
        // that a code_verifier must be provided when a code_challenge was present.
        //
        // By overriding the auth context and not the code verifier, the latter
        // will be missing during code redemption, causing the expected failure.
        TestOpts opts = TestOpts.getDefault().setAuthContext(apiFlow.authContext());

        testFailingCodeRedemption(
                sdJwt,
                opts,
                HttpStatus.SC_BAD_REQUEST,
                OAuthErrorException.INVALID_GRANT,
                "Authorization code verifier not valid");
    }

    @Test
    public void shouldRejectAuthorizationCodeRedemptionWithInvalidVerifier() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        ApiFlowData apiFlow = startApiAuthorizationRequest();
        TestOpts opts =
                TestOpts.getDefault().setAuthContext(apiFlow.authContext()).setCodeVerifier("invalid-code-verifier");

        testFailingCodeRedemption(
                sdJwt,
                opts,
                HttpStatus.SC_BAD_REQUEST,
                OAuthErrorException.INVALID_GRANT,
                "Authorization code verifier not valid");
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
    public void shouldAuthenticateSuccessfully_NewDcSdJwtFormat() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication and assert final-spec DCQL format usage.
        TestOpts opts = TestOpts.getDefault();
        TestFlowData testFlowData = testSuccessfulAuthenticationVerbose(sdJwt, opts);
        var credentialQuery =
                testFlowData.requestObject().getDcqlQuery().getCredentials().getFirst();
        assertEquals("dc+sd-jwt", credentialQuery.getFormat());
        assertNotNull(
                testFlowData.requestObject().getClientMetadata().getVpFormat().getDcSdJwt());
        assertAuthenticatingUser(opts, testFlowData.authCode());
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
    public void shouldAuthenticateSuccessfully_SchemedAud() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Prefix aud with scheme)
        String aud = "x509_san_dns:%s".formatted(getVerifierClientId());
        TestOpts opts = TestOpts.getDefault().setOverridePresentationAud(aud);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithDualCredentialProfile() throws Exception {
        AuthenticatorConfigRepresentation originalConfig = getAuthenticatorConfig();
        try {
            AuthenticatorConfigRepresentation updatedConfig = getAuthenticatorConfig();
            updatedConfig.getConfig().put("profiles", dualProfileConfigJson());
            updatedConfig.getConfig().put("enforceRevocationStatus", "false");
            updateAuthenticatorConfig(updatedConfig);

            ApiFlowData apiFlow = startApiAuthorizationRequest(DUAL_PROFILE_ID);
            assertNull(apiFlow.authContext().getProfileId(), "Profile id must not be leaked to the wallet");

            RequestObject requestObject =
                    resolveRequestObject(apiFlow.authContext().getAuthorizationRequest());
            assertEquals(2, requestObject.getDcqlQuery().getCredentials().size());
            assertEquals(
                    List.of("primary", "supporting"),
                    requestObject.getDcqlQuery().getCredentials().stream()
                            .map(credential -> credential.getId())
                            .toList());

            String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);
            TestOpts opts =
                    TestOpts.getDefault().setAuthContext(apiFlow.authContext()).setCodeVerifier(apiFlow.codeVerifier());

            testSuccessfulAuthentication(sdJwt, opts);
        } finally {
            updateAuthenticatorConfig(originalConfig);
        }
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
        assertEquals(ProcessingError.INVALID_VP_TOKEN.getErrorString(), errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains("Could not parse SD-JWT VP token contained in `vp_token`"));
    }

    @Test
    public void shouldRejectWalletErrorResponseWithMismatchingState() throws Exception {
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        HttpResponse response = sendAuthorizationErrorResponse(
                requestObject, OAuthErrorException.ACCESS_DENIED, "End-User denied consent", "wrong-state");
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(response);
        assertEquals(OAuthErrorException.INVALID_REQUEST, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains("State param must match requestId"));

        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.PENDING, statusPayload.getStatus());
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
                "Could not parse SD-JWT VP token contained in `vp_token`");
    }

    @Test
    public void shouldFailAuthentication_NonMatchingDcqlCredentialId() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);

        // Retrieve an authorization request and deliberately respond under a non-matching DCQL credential query ID.
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        requestObject.getDcqlQuery().getCredentials().getFirst().setId("non-matching-dcql-credential-id");

        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, TestOpts.getDefault());
        assertFailingAuthentication(
                response,
                authContext.getTransactionId(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "Presented vp_token map must contain exactly one token for credential");
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
                getVerifierClientId(), // Missing required client_id prefix
                ":" + getVerifierClientId(), // Missing scheme
                "double:scheme:" + getVerifierClientId());

        for (String invalidAud : invalidAuds) {
            testFailAuthentication_InvalidKbJwt(
                    null, invalidAud, null, null, "claim 'aud' does not match actual value");
        }
    }

    private AuthenticatorConfigRepresentation getAuthenticatorConfig() {
        return getActiveTestRealmResource().flows().getAuthenticatorConfig(TEST_REALM_SD_JWT_AUTH_CONFIG_ID);
    }

    private void updateAuthenticatorConfig(AuthenticatorConfigRepresentation config) {
        getActiveTestRealmResource().flows().updateAuthenticatorConfig(config.getId(), config);
    }

    private String dualProfileConfigJson() {
        return """
                [
                  {
                    "id": "default",
                    "displayCta": { "en": "Sign in with a wallet" },
                    "credentials": [
                      {
                        "id": "identity",
                        "role": "primary",
                        "credentialTypes": ["%s", "%s"],
                        "claims": ["sub", "username"]
                      }
                    ]
                  },
                  {
                    "id": "%s",
                    "displayCta": { "en": "Sign in with two credentials" },
                    "credentials": [
                      {
                        "id": "primary",
                        "role": "primary",
                        "credentialTypes": ["%s"],
                        "claims": ["sub", "username"]
                      },
                      {
                        "id": "supporting",
                        "role": "supporting",
                        "credentialTypes": ["%s"],
                        "claims": ["username"],
                        "trust": [{ "type": "self" }],
                        "binding": [
                          {
                            "type": "claim_equals_primary_claim",
                            "credentialClaim": "username",
                            "primaryCredentialClaim": "username"
                          }
                        ]
                      }
                    ]
                  }
                ]
                """.formatted(
                        VCT_CONFIG_DEFAULT, VCT_CONFIG_ALT, DUAL_PROFILE_ID, VCT_CONFIG_DEFAULT, VCT_CONFIG_DEFAULT);
    }
}
