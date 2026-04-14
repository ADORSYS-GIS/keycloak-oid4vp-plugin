package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationResponseService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jwk.JWK;
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
        // Retrieve an authorization request
        ApiFlowData apiFlow = opts.getAuthContext() == null ? startApiAuthorizationRequest() : null;
        AuthorizationContext authContext =
                Optional.ofNullable(opts.getAuthContext()).orElseGet(() -> apiFlow.authContext());
        String codeVerifier = Optional.ofNullable(opts.getCodeVerifier())
                .orElseGet(() -> apiFlow == null ? null : apiFlow.codeVerifier());
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());

        // Prepare and send the OpenID4VP response to Keycloak
        HttpResponse response = sendAuthorizationResponse(sdJwt, requestObject, opts);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());

        // Check auth status
        HttpResponse statusResponse = fetchAuthenticationStatus(authContext.getTransactionId());
        AuthorizationContext statusPayload = parseAuthorizationContext(statusResponse);
        assertEquals(AuthorizationContextStatus.SUCCESS, statusPayload.getStatus());

        // Redeem authorization code when it is not disclosed in the status response
        String authCode = statusPayload.getAuthorizationCode();
        if (authCode == null) {
            assertNotNull(codeVerifier, "Code verifier should not be null for API flows");
            authCode = redeemAuthorizationCode(authContext.getTransactionId(), codeVerifier);
        }

        assertNotNull(authCode, "Authorization code should not be null");
        if (opts.shouldRetrieveAccessToken()) {
            assertAuthenticatingUser(opts, authCode);
        }

        // Bubble up authorization code
        return authCode;
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
        if (opts.shouldPrepareLegacyResponse()) {
            oid4vpResponse = prepareLegacyOpenID4VPResponse(sdJwtVpToken, requestObject, opts);
        } else {
            oid4vpResponse = prepareOpenID4VPResponse(sdJwtVpToken, requestObject);
        }

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
    private List<BasicNameValuePair> prepareOpenID4VPResponse(String sdJwtVpToken, RequestObject requestObject)
            throws IOException {
        // Build presentation submission
        DcqlQuery dcqlQuery = requestObject.getDcqlQuery();
        Credential credentialQuery = dcqlQuery.getCredentials().getFirst();
        var vpTokenMap = Map.of(credentialQuery.getId(), List.of(sdJwtVpToken));

        // Compose the response object as form-urlencoded parameters
        return new ArrayList<>(List.of(
                new BasicNameValuePair(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap)),
                new BasicNameValuePair(ResponseObject.STATE_KEY, requestObject.getState())));
    }

    /**
     * Prepare the OpenID4VP response object to be sent to Keycloak (Legacy).
     *
     * @param sdJwtVpToken  the SD-JWT verifiable presentation token
     * @param requestObject the request object containing the presentation definition
     */
    private List<BasicNameValuePair> prepareLegacyOpenID4VPResponse(
            String sdJwtVpToken, RequestObject requestObject, TestOpts opts) throws IOException {
        // Build presentation submission

        PresentationDefinition definition = requestObject.getPresentationDefinition();
        InputDescriptor inputDescriptor = definition.getInputDescriptors().getFirst();

        PresentationSubmission submission = new PresentationSubmission();
        submission.setId(UUID.randomUUID().toString());
        submission.setDefinitionId(definition.getId());

        // Build descriptor
        // noinspection ExtractMethodRecommender

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

    /**
     * POJO for test options.
     */
    public static class TestOpts {

        private String testUser = TEST_USER;
        private AuthorizationContext authContext;
        private String codeVerifier;
        private boolean shouldBase64EncodeVpToken;
        private boolean shouldRetrieveAccessToken = true;
        private boolean shouldPrepareLegacyResponse = true;
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

        public AuthorizationContext getAuthContext() {
            return authContext;
        }

        public TestOpts setAuthorizationContext(AuthorizationContext authContext) {
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

        public boolean shouldPrepareLegacyResponse() {
            return shouldPrepareLegacyResponse;
        }

        public TestOpts setShouldPrepareLegacyResponse(boolean shouldPrepareLegacyResponse) {
            this.shouldPrepareLegacyResponse = shouldPrepareLegacyResponse;
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
