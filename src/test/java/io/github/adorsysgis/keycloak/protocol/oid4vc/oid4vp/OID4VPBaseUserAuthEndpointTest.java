package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing framework for end-to-end OpenID4VC scenarios.
 */
public abstract class OID4VPBaseUserAuthEndpointTest extends OID4VPBaseKeycloakTest {

    protected final SdJwtVPTestUtils sdJwtVPTestUtils = new SdJwtVPTestUtils(keycloak, getActiveTestRealm());

    /**
     * Helper for successful flows.
     */
    protected String testSuccessfulAuthentication(String sdJwt, TestOpts opts) throws Exception {
        TestFlowData testFlowData = testSuccessfulAuthenticationVerbose(sdJwt, opts);

        // Exchange authorization code for access token
        String authCode = testFlowData.authCode();
        assertNotNull(authCode, "Authorization code should not be null");
        if (opts.shouldRetrieveAccessToken()) {
            assertAuthenticatingUser(opts, authCode);
        }

        // Bubble up authorization code
        return authCode;
    }

    /**
     * Helper for successful flows (verbose)
     * @return contextual data for further assertions
     */
    protected TestFlowData testSuccessfulAuthenticationVerbose(String sdJwt, TestOpts opts) throws Exception {
        // Retrieve an authorization request
        ApiFlowData apiFlow = resolveApiFlow(opts);
        AuthorizationContext authContext = apiFlow.authContext();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);
        ResponseToWallet responseToWallet = parseHttpResponse(response, ResponseToWallet.class);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // If auth context acquired in place, then cross-device flow assumed.
        // Assert that response to wallet does not contain a redirect URI.
        if (opts.getAuthContext() == null) {
            assertNull(
                    responseToWallet.getRedirectUri(),
                    "Response to wallet should not contain a redirect URI in cross-device flow");
        }

        // Check auth status
        String authCode = null;
        if (authContext.getTransactionId() != null) {
            AuthorizationContext statusPayload = assertSuccessfulAuthorizationStatus(apiFlow);

            // Redeem authorization code when it is not disclosed in the status response
            authCode = statusPayload.getAuthorizationCode();
            if (authCode == null) {
                assertNotNull(apiFlow.codeVerifier(), "Code verifier should not be null for API flows");
                authCode = redeemAuthorizationCode(apiFlow.authContext().getTransactionId(), apiFlow.codeVerifier());
            }
        }

        // Bubble up test flow data
        return new TestFlowData(authContext, requestObject, responseToWallet, authCode);
    }

    /**
     * Assert the identity of the authenticated user.
     */
    protected void assertAuthenticatingUser(TestOpts opts, String authCode) throws VerificationException, IOException {
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
    protected void testFailingAuthentication(
            String sdJwt, TestOpts opts, int httpStatus, String expectedError, String expectedErrorDescription)
            throws Exception {
        // Retrieve an authorization request
        AuthorizationContext authContext =
                Optional.ofNullable(opts.getAuthContext()).orElseGet(this::requestAuthorizationRequest);

        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);

        // Run assertions
        assertFailingAuthentication(
                response, authContext.getTransactionId(), httpStatus, expectedError, expectedErrorDescription);
    }

    /**
     * Helper for failing flows (from VP token).
     */
    protected void testFailingAuthenticationWithVPToken(
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
     * Helper for flows that should fail at authorization code redemption.
     */
    protected void testFailingCodeRedemption(
            String sdJwt, TestOpts opts, int httpStatus, String expectedError, String expectedErrorDescription)
            throws Exception {
        ApiFlowData apiFlow = resolveApiFlow(opts);
        RequestObject requestObject = resolveRequestObject(apiFlow.authContext().getAuthorizationRequest());

        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        assertSuccessfulAuthorizationStatus(apiFlow);

        HttpResponse redemptionResponse =
                redeemAuthorizationCodeResponse(apiFlow.authContext().getTransactionId(), apiFlow.codeVerifier());
        assertEquals(httpStatus, redemptionResponse.getStatusLine().getStatusCode());

        OAuth2ErrorRepresentation errorRep = parseErrorResponse(redemptionResponse);
        assertEquals(expectedError, errorRep.getError());
        assertTrue(errorRep.getErrorDescription().contains(expectedErrorDescription));
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

    private ApiFlowData resolveApiFlow(TestOpts opts) {
        if (opts.getAuthContext() != null) {
            return new ApiFlowData(opts.getAuthContext(), opts.getCodeVerifier());
        }

        ApiFlowData apiFlow = startApiAuthorizationRequest();
        if (opts.getCodeVerifier() != null) {
            return new ApiFlowData(apiFlow.authContext(), opts.getCodeVerifier());
        }
        return apiFlow;
    }

    private AuthorizationContext assertSuccessfulAuthorizationStatus(ApiFlowData apiFlow) throws Exception {
        HttpResponse statusResponse =
                fetchAuthenticationStatus(apiFlow.authContext().getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.SUCCESS, statusPayload.getStatus());

        if (apiFlow.codeVerifier() != null) {
            assertNull(statusPayload.getAuthorizationCode(), "authorization_code must stay hidden for API flows");
        }

        return statusPayload;
    }

    /**
     * Helper for failing flows (Invalid KB-JWTs).
     */
    protected void testFailAuthentication_InvalidKbJwt(
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
    protected HttpResponse sendAuthorizationResponse(String sdJwt, RequestObject requestObject, TestOpts opts)
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
    protected HttpResponse sendAuthorizationResponseWithVPToken(
            String sdJwtVpToken, RequestObject requestObject, TestOpts opts) throws Exception {
        // Wrap the SD-JWT VP in an OpenID4VP response
        List<BasicNameValuePair> oid4vpResponse;
        if (!opts.shouldForceUnencryptedResponse()
                && requestObject.getClientMetadata().getJwks() != null) {
            oid4vpResponse = prepareEncryptedOpenID4VPResponse(sdJwtVpToken, requestObject);
        } else {
            oid4vpResponse = prepareOpenID4VPResponse(sdJwtVpToken, requestObject);
        }

        // Send the OpenID4VP response to Keycloak
        String url = requestObject.getResponseUri();
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
    private List<BasicNameValuePair> prepareOpenID4VPResponse(String sdJwtVpToken, RequestObject requestObject)
            throws IOException {
        // Build presentation submission
        var vpTokenMap = prepareVpTokenMap(sdJwtVpToken, requestObject);

        // Compose the response object as form-urlencoded parameters
        return new ArrayList<>(List.of(
                new BasicNameValuePair(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap)),
                new BasicNameValuePair(ResponseObject.STATE_KEY, requestObject.getState())));
    }

    /**
     * Prepare an encrypted OpenID4VP response object to be sent to Keycloak.
     *
     * @param sdJwtVpToken  the SD-JWT verifiable presentation token
     * @param requestObject the request object containing the presentation definition
     */
    private List<BasicNameValuePair> prepareEncryptedOpenID4VPResponse(String sdJwtVpToken, RequestObject requestObject)
            throws IOException {
        // Build presentation submission
        var vpTokenMap = prepareVpTokenMap(sdJwtVpToken, requestObject);
        var respMap = Map.of(ResponseObject.VP_TOKEN_KEY, vpTokenMap);
        String resp = JsonSerialization.writeValueAsString(respMap);

        // Read encryption key from request object
        JWK encJwk = requestObject.getClientMetadata().getJwks().getKeys()[0];
        ECPublicKey encKey = (ECPublicKey) JWKParser.create(encJwk).toPublicKey();

        // Encrypt the vpTokenMap
        String encResp = ECTestUtils.encryptMessage(resp, encKey);

        // Compose the response object as form-urlencoded parameters
        return new ArrayList<>(List.of(new BasicNameValuePair("response", encResp)));
    }

    /**
     * Maps VP token to credential query ID.
     */
    private Map<String, List<String>> prepareVpTokenMap(String sdJwtVpToken, RequestObject requestObject) {
        DcqlQuery dcqlQuery = requestObject.getDcqlQuery();
        Credential credentialQuery = dcqlQuery.getCredentials().getFirst();
        return Map.of(credentialQuery.getId(), List.of(sdJwtVpToken));
    }

    public record TestFlowData(
            AuthorizationContext authContext,
            RequestObject requestObject,
            ResponseToWallet responseToWallet,
            String authCode) {}

    /**
     * POJO for test options.
     */
    public static class TestOpts {

        private String testUser = TEST_USER;
        private AuthorizationContext authContext;
        private String codeVerifier;
        private boolean shouldBase64EncodeVpToken;
        private boolean shouldRetrieveAccessToken = true;
        private boolean shouldEnforceRedirectUri = false;
        private boolean shouldForceUnencryptedResponse = false;
        private String overridePresentationAud;

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

        public AuthorizationContext getAuthContext() {
            return authContext;
        }

        public TestOpts setAuthContext(AuthorizationContext authContext) {
            this.authContext = authContext;
            return this;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public TestOpts setCodeVerifier(String codeVerifier) {
            this.codeVerifier = codeVerifier;
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

        public boolean shouldForceUnencryptedResponse() {
            return shouldForceUnencryptedResponse;
        }

        public TestOpts setShouldForceUnencryptedResponse(boolean shouldForceUnencryptedResponse) {
            this.shouldForceUnencryptedResponse = shouldForceUnencryptedResponse;
            return this;
        }

        public String getOverridePresentationAud() {
            return overridePresentationAud;
        }

        public TestOpts setOverridePresentationAud(String overridePresentationAud) {
            this.overridePresentationAud = overridePresentationAud;
            return this;
        }
    }
}
