package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.ALTERNATIVE_PRIMARY_CREDENTIAL_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.PRIMARY_CREDENTIAL_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.SUPPORTING_CREDENTIAL_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint.REQUEST_JWT_PATH;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase.pruneAuthSessionId;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.RESPONSE_MODE_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.AUTH_REQ_JWT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.KeycloakTestContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlQueryGeneratorTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.EudiPidTrustListTestServer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
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
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing OpenID4VP user authentication via presentation of identity credentials.
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
        DcqlQueryGeneratorTest.assertDcqlQuery(
                requestObject.getDcqlQuery(),
                List.of(CREDENTIAL_TYPES_CONFIG_DEFAULT, VCT_CONFIG_ALT),
                List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME));

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
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Start a valid API authorization flow which generates a code_challenge.
        ApiFlowData apiFlow = startApiAuthorizationRequest();

        // This test will fail because the server enforces
        // that a code_verifier must be provided when a code_challenge was present.
        //
        // By overriding the auth context and not the code verifier, the latter
        // will be missing during code redemption, causing the expected failure.
        TestOpts opts = TestOpts.getDefault().setAuthContext(apiFlow.authContext());

        testFailingCodeRedemption(sdJwt, opts);
    }

    @Test
    public void shouldRejectAuthorizationCodeRedemptionWithInvalidVerifier() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        ApiFlowData apiFlow = startApiAuthorizationRequest();
        TestOpts opts =
                TestOpts.getDefault().setAuthContext(apiFlow.authContext()).setCodeVerifier("invalid-code-verifier");

        testFailingCodeRedemption(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_SdJwtWithoutKid() throws Exception {
        // Request a valid SD-JWT credential from Keycloak without explicit kid
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER, false, true);

        // Proceed to authentication
        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldAuthenticateSuccessfully_NewDcSdJwtFormat() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication and assert final-spec DCQL format usage.
        TestOpts opts = TestOpts.getDefault();
        TestFlowData testFlowData = testSuccessfulAuthenticationVerbose(sdJwt, opts);
        var credentialQuery =
                testFlowData.requestObject().getDcqlQuery().getCredentials().getFirst();
        assertEquals("dc+sd-jwt", credentialQuery.getFormat());
        assertNotNull(
                testFlowData.requestObject().getClientMetadata().getVpFormat().getDcSdJwt());
        assertNull(
                testFlowData.requestObject().getClientMetadata().getVpFormat().getJwtVcJson());
        assertAuthenticatingUser(opts, testFlowData.authCode());
    }

    @Test
    public void shouldAuthenticateSuccessfully_Base64EncodedVpToken() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Base64-encoded VP token)
        TestOpts opts = TestOpts.getDefault().setShouldBase64EncodeVpToken(true);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_SchemedAud() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Prefix aud with scheme)
        String aud = "x509_san_dns:%s".formatted(getVerifierClientId());
        TestOpts opts = TestOpts.getDefault().setOverridePresentationAud(aud);
        testSuccessfulAuthentication(sdJwt, opts);
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithDualCredentialProfile() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.dualProfile(), (apiFlow, requestObject) -> {
            assertNull(apiFlow.authContext().getProfileId(), "Profile id must not be leaked to the wallet");
            assertEquals(2, requestObject.getDcqlQuery().getCredentials().size());
            assertEquals(
                    List.of(PRIMARY_CREDENTIAL_ID, SUPPORTING_CREDENTIAL_ID),
                    requestObject.getDcqlQuery().getCredentials().stream()
                            .map(Credential::getId)
                            .toList());

            String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
            TestOpts opts =
                    TestOpts.getDefault().setAuthContext(apiFlow.authContext()).setCodeVerifier(apiFlow.codeVerifier());

            testSuccessfulAuthentication(sdJwt, opts);
        });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithAlternativePrimaryCredentialGroup() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.alternativePrimary(), (apiFlow, requestObject) -> {
            assertEquals(2, requestObject.getDcqlQuery().getCredentials().size());
            assertEquals(
                    List.of(List.of(PRIMARY_CREDENTIAL_ID), List.of(ALTERNATIVE_PRIMARY_CREDENTIAL_ID)),
                    requestObject.getDcqlQuery().getCredentialSets().getFirst().getOptions());

            String sdJwtVpToken = presentSdJwt(requestObject);
            TestOpts opts =
                    TestOpts.getDefault().setAuthContext(apiFlow.authContext()).setCodeVerifier(apiFlow.codeVerifier());

            testSuccessfulAuthenticationWithVPTokenMap(Map.of(ALTERNATIVE_PRIMARY_CREDENTIAL_ID, sdJwtVpToken), opts);
        });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithMdocPrimaryCredential() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.mdocPrimary(), (apiFlow, requestObject) -> {
            Credential mdocCredential =
                    requestObject.getDcqlQuery().getCredentials().getFirst();
            assertEquals("mso_mdoc", mdocCredential.getFormat());
            assertEquals(MdocBaseTest.DOC_TYPE, mdocCredential.getMeta().getDoctypeValue());

            Map<String, Object> mdocClaims = Map.of(
                    MdocBaseTest.NAMESPACE,
                    Map.of(JsonWebToken.SUBJECT, TEST_USER_ID, OAuth2Constants.USERNAME, TEST_USER));
            String mdocToken = presentMdoc(requestObject, mdocClaims);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testSuccessfulAuthenticationWithVPTokenMap(Map.of(PRIMARY_CREDENTIAL_ID, mdocToken), opts);
        });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithMdocIssuerResolvedFromSignedPidTrustList() throws Exception {
        EudiPidTrustListTestServer trustListServer = KeycloakTestContainer.eudiPidTrustListServer();
        trustListServer.serveSignedTrustList();

        AuthenticationProfileSamples.ProfileSample profile =
                AuthenticationProfileSamples.mdocPrimaryWithEudiPidTrustList(
                        trustListServer.urlFromKeycloakContainer(),
                        MdocBaseTest.getIssuerCertBase64(),
                        EudiPidTrustListTestServer.PROVIDER_A_ID);

        withAuthenticationProfile(profile, (apiFlow, requestObject) -> {
            Map<String, Object> claims = Map.of(MdocBaseTest.NAMESPACE, Map.of(JsonWebToken.SUBJECT, TEST_USER_ID));
            String mdocToken = presentMdoc(requestObject, claims);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testSuccessfulAuthenticationWithVPTokenMap(Map.of(PRIMARY_CREDENTIAL_ID, mdocToken), opts);
        });
    }

    @Test
    public void shouldRejectSameSubjectMdocFromDifferentProviderInSignedPidTrustList() throws Exception {
        EudiPidTrustListTestServer trustListServer = KeycloakTestContainer.eudiPidTrustListServer();
        trustListServer.serveSignedTrustList();

        AuthenticationProfileSamples.ProfileSample profile =
                AuthenticationProfileSamples.mdocPrimaryWithEudiPidTrustList(
                        trustListServer.urlFromKeycloakContainer(),
                        MdocBaseTest.getIssuerCertBase64(),
                        EudiPidTrustListTestServer.PROVIDER_A_ID);

        withAuthenticationProfile(profile, (apiFlow, requestObject) -> {
            // Provider B is trusted by the same LoTE and deliberately carries Alice's exact
            // subject. It must still fail because this profile selected Provider A.
            Map<String, Object> claims = Map.of(MdocBaseTest.NAMESPACE, Map.of(JsonWebToken.SUBJECT, TEST_USER_ID));
            String mdocToken = MdocBaseTest.buildMdocVpToken(
                    requestObject,
                    claims,
                    MdocBaseTest.DOC_TYPE,
                    MdocBaseTest.getIssuerKeyRef2(),
                    MdocBaseTest.getIssuerCertRef2());

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testFailingAuthenticationWithVPTokenMap(
                    Map.of(PRIMARY_CREDENTIAL_ID, mdocToken),
                    opts,
                    HttpStatus.SC_UNAUTHORIZED,
                    ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                    "Certificate chain validation failed");
        });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithMdocPrimaryCredential_MdlIdentityClaim() throws Exception {
        // Regression for issue 001: a standard ISO 18013-5 mDL carries no sub claim, so
        // identity must be derivable from a configured standard mDL claim (document_number).
        withAuthenticationProfile(
                AuthenticationProfileSamples.mdocPrimaryWithMdlIdentity(), (apiFlow, requestObject) -> {
                    Map<String, Object> mdocClaims = Map.of(
                            MdocBaseTest.NAMESPACE, Map.of("document_number", TEST_USER_ID, "given_name", "Alice"));
                    String mdocToken = presentMdoc(requestObject, mdocClaims);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);

                    testSuccessfulAuthenticationWithVPTokenMap(Map.of(PRIMARY_CREDENTIAL_ID, mdocToken), opts);
                });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithMdocPrimaryCredential_EncryptedResponse_IsoTranscript()
            throws Exception {
        // Wallet-generated nonce, conveyed Base64URL-encoded in the JWE `apu` header. The server
        // extracts it and binds the mDoc device signature to the ISO-spec session transcript.
        String mdocGeneratedNonce = "mdoc-generated-nonce-9f3a7c";

        withAuthenticationProfile(
                AuthenticationProfileSamples.mdocPrimary(),
                Map.of(
                        RESPONSE_MODE_CONFIG,
                        ResponseMode.DIRECT_POST_JWT.getValue(),
                        FALLBACK_TO_ISO_SPEC_SESSION_TRANSCRIPT_CONFIG,
                        "true"),
                (apiFlow, requestObject) -> {
                    // Encrypted responses advertise an ephemeral JWK set for response encryption.
                    assertNotNull(requestObject.getClientMetadata().getJwks());

                    Map<String, Object> mdocClaims = Map.of(
                            MdocBaseTest.NAMESPACE,
                            Map.of(JsonWebToken.SUBJECT, TEST_USER_ID, OAuth2Constants.USERNAME, TEST_USER));
                    String mdocToken = MdocBaseTest.buildMdocVpToken(
                            requestObject, mdocClaims, MdocBaseTest.DOC_TYPE, mdocGeneratedNonce, true);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            // Let the framework encrypt the response (direct_post.jwt) and inject
                            // the mdocGeneratedNonce into the JWE `apu` header.
                            .setResponseApu(mdocGeneratedNonce);

                    testSuccessfulAuthenticationWithVPTokenMap(Map.of(PRIMARY_CREDENTIAL_ID, mdocToken), opts);
                });
    }

    @Test
    public void shouldAuthenticateSuccessfully_WithSdJwtPrimaryAndMdocSupporting() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.sdjwtMdocDual(), (apiFlow, requestObject) -> {
            assertEquals(2, requestObject.getDcqlQuery().getCredentials().size());
            assertEquals(
                    List.of(PRIMARY_CREDENTIAL_ID, SUPPORTING_CREDENTIAL_ID),
                    requestObject.getDcqlQuery().getCredentials().stream()
                            .map(Credential::getId)
                            .toList());

            String sdJwtVpToken = presentSdJwt(requestObject);
            Map<String, Object> mdocClaims =
                    Map.of(MdocBaseTest.NAMESPACE, Map.of(OAuth2Constants.USERNAME, TEST_USER));
            String mdocToken = presentMdoc(requestObject, mdocClaims);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testSuccessfulAuthenticationWithVPTokenMap(
                    Map.of(PRIMARY_CREDENTIAL_ID, sdJwtVpToken, SUPPORTING_CREDENTIAL_ID, mdocToken), opts);
        });
    }

    @Test
    public void shouldAuthenticateSuccessfully_DoubleSchemedAud() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Proceed to authentication (Prefix aud with scheme twice)
        String aud = "x509_san_dns:x509_san_dns:%s".formatted(getVerifierClientId());
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
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

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
        assertTrue(errorRep.getErrorDescription().contains("Could not parse credential token contained in `vp_token`"));
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
                "Could not parse credential token contained in `vp_token`");
    }

    @Test
    public void shouldFailAuthentication_NonMatchingDcqlCredentialId() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

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
                "Presented vp_token map contains unknown credential(s): [non-matching-dcql-credential-id]");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithUnexpectedVct() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential("https://this-vct-is-not-expected.com", TEST_USER);

        // DCQL presentation validation rejects vct before the authenticator runs
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "Presented SD-JWT vct does not match any value in meta.vct_values");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithNoSubject() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, null, TEST_USER);

        // DCQL presentation validation rejects missing requested claims before the authenticator runs
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "Presented SD-JWT does not satisfy DCQL claim path: [sub]");
    }

    @Test
    public void shouldRespectHolderBindingRequirementForSdJwtWithoutKeyBindingJwt() throws Exception {
        // Request a valid SD-JWT credential from Keycloak to use for authentication
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        // Build an auth request to inspect holder-binding requirement used by runtime DCQL.
        AuthorizationContext authContext = requestAuthorizationRequest();
        RequestObject requestObject = resolveRequestObject(authContext.getAuthorizationRequest());
        boolean requireHolderBinding = Boolean.TRUE.equals(
                requestObject.getDcqlQuery().getCredentials().getFirst().getRequireCryptographicHolderBinding());

        // This test specifically verifies "missing KB-JWT" rejection and only applies where
        // the runtime DCQL query requires holder binding.
        assumeTrue(requireHolderBinding, "Holder binding is not required in this runtime configuration");

        // Send issuer-signed SD-JWT directly as vp_token (no KB-JWT attached) and assert
        // DCQL layer rejects early with invalid_vp_token.
        HttpResponse response = sendAuthorizationResponseWithVPToken(
                sdJwt, requestObject, TestOpts.getDefault().setAuthContext(authContext));
        assertFailingAuthentication(
                response,
                authContext.getTransactionId(),
                HttpStatus.SC_BAD_REQUEST,
                ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                "DCQL query requires cryptographic holder binding");
    }

    @Test
    public void shouldFailAuthentication_IfUserUnknown() throws Exception {
        // Request a SD-JWT credential from Keycloak to use for authentication.
        String testSubject = "unknown-user-id";
        String testUsername = "unknown-user";
        String sdJwt =
                sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, testSubject, testUsername);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented OID4VP credential is unknown");
    }

    @Test
    public void shouldFailAuthentication_WhenSubjectIsUnknownEvenWithValidUsername() throws Exception {
        // Request SD-JWT credentials with an unknown subject but valid username
        String testSubject = "unknown-user-id";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, testSubject, TEST_USER);

        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented OID4VP credential is unknown");
    }

    @Test
    public void shouldIgnoreUsernameClaim_WhenSubjectResolvesUser() throws Exception {
        // A legacy or custom profile may still request username, but it is not used
        // for user resolution or identity validation.
        String sdJwt =
                sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER_ID, "other-user");

        testSuccessfulAuthentication(sdJwt, TestOpts.getDefault());
    }

    @Test
    public void shouldFailAuthentication_IfUserDisabled() throws Exception {
        String disabledUser = "disabled-user";
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, disabledUser);

        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented OID4VP credential is disabled");
    }

    @Test
    public void shouldFailAuthentication_SdJwtWithoutStatusClaim() throws Exception {
        // Request SD-JWT credentials from Keycloak to use for authentication
        // Token status is enforced, but we omit the status claim, causing authentication to fail
        String sdJwt =
                sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER, false, false);

        // Proceed to authentication
        testFailingAuthentication(
                sdJwt,
                TestOpts.getDefault(),
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid OID4VP credential presentation: Primary credential verification failed: Token status verification failed for credential to requirement 'identity'");
    }

    @Test
    public void shouldFailAuthentication_SdJwtSignedWithDisabledKey() throws Exception {
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(
                CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER, true, true, SdJwtVPTestUtils.getDisabledKeycloakJwk());

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
                "x509_hash:x509_san_dns:" + getVerifierClientId(), // Double scheming of different prefixes
                "double:scheme:" + getVerifierClientId());

        for (String invalidAud : invalidAuds) {
            testFailAuthentication_InvalidKbJwt(
                    null, invalidAud, null, null, "claim 'aud' does not match actual value");
        }
    }

    @Test
    public void shouldFailAuthentication_IfMdocSupportingCredentialMissing() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.sdjwtMdocDual(), (apiFlow, requestObject) -> {
            String sdJwtVpToken = presentSdJwt(requestObject);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testFailingAuthenticationWithVPTokenMap(
                    Map.of(PRIMARY_CREDENTIAL_ID, sdJwtVpToken),
                    opts,
                    HttpStatus.SC_BAD_REQUEST,
                    ProcessingError.INVALID_VP_TOKEN.getErrorString(),
                    "Presented vp_token map does not satisfy DCQL credential_sets");
        });
    }

    @Test
    public void shouldFailAuthentication_IfMdocRequiredClaimsMissingOrBlank() throws Exception {
        record FailureCase(
                Map<String, Object> claims, int httpStatus, ProcessingError error, String errorDescription) {}

        List<FailureCase> cases = List.of(
                new FailureCase(
                        Map.of(MdocBaseTest.NAMESPACE, Map.of()),
                        HttpStatus.SC_BAD_REQUEST,
                        ProcessingError.INVALID_VP_TOKEN,
                        "Presented mDoc does not satisfy DCQL claim path: [com.example.namespace1, username]"),
                new FailureCase(
                        Map.of(MdocBaseTest.NAMESPACE, Map.of(OAuth2Constants.USERNAME, "")),
                        HttpStatus.SC_UNAUTHORIZED,
                        ProcessingError.VP_TOKEN_AUTH_ERROR,
                        "Required claim is blank: com.example.namespace1/username"));

        for (FailureCase failureCase : cases) {
            withAuthenticationProfile(AuthenticationProfileSamples.sdjwtMdocDual(), (apiFlow, requestObject) -> {
                String sdJwtVpToken = presentSdJwt(requestObject);
                String mdocToken = presentMdoc(requestObject, failureCase.claims());

                TestOpts opts = TestOpts.getDefault()
                        .setAuthContext(apiFlow.authContext())
                        .setCodeVerifier(apiFlow.codeVerifier())
                        .setShouldForceUnencryptedResponse(true);

                testFailingAuthenticationWithVPTokenMap(
                        Map.of(PRIMARY_CREDENTIAL_ID, sdJwtVpToken, SUPPORTING_CREDENTIAL_ID, mdocToken),
                        opts,
                        failureCase.httpStatus(),
                        failureCase.error().getErrorString(),
                        failureCase.errorDescription());
            });
        }
    }

    @Test
    public void shouldFailAuthentication_IfMdocSupportingBindingRuleFails() throws Exception {
        withAuthenticationProfile(AuthenticationProfileSamples.sdjwtMdocDual(), (apiFlow, requestObject) -> {
            String sdJwtVpToken = presentSdJwt(requestObject);
            Map<String, Object> mdocClaims =
                    Map.of(MdocBaseTest.NAMESPACE, Map.of(OAuth2Constants.USERNAME, "other-user"));
            String mdocToken = presentMdoc(requestObject, mdocClaims);

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testFailingAuthenticationWithVPTokenMap(
                    Map.of(PRIMARY_CREDENTIAL_ID, sdJwtVpToken, SUPPORTING_CREDENTIAL_ID, mdocToken),
                    opts,
                    HttpStatus.SC_UNAUTHORIZED,
                    ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                    "Invalid OID4VP credential presentation: Supporting credential verification failed: Credential 'supporting' failed binding rule 'claim_equals_primary_claim'");
        });
    }

    @Test
    public void shouldFailAuthentication_IfMdocIssuerCertNotTrusted() throws Exception {
        // Configure the primary mDoc credential with a trust anchor that does NOT match the
        // issuer certificate used to sign the device response (ISO 18013-5 spec sample cert).
        withAuthenticationProfile(
                AuthenticationProfileSamples.mdocPrimaryWithAnchor(MdocBaseTest.getSpecSampleCert()),
                (apiFlow, requestObject) -> {
                    Map<String, Object> mdocClaims = Map.of(
                            MdocBaseTest.NAMESPACE,
                            Map.of(JsonWebToken.SUBJECT, TEST_USER_ID, OAuth2Constants.USERNAME, TEST_USER));
                    String mdocToken = presentMdoc(requestObject, mdocClaims);

                    TestOpts opts = TestOpts.getDefault()
                            .setAuthContext(apiFlow.authContext())
                            .setCodeVerifier(apiFlow.codeVerifier())
                            .setShouldForceUnencryptedResponse(true);

                    testFailingAuthenticationWithVPTokenMap(
                            Map.of(PRIMARY_CREDENTIAL_ID, mdocToken),
                            opts,
                            HttpStatus.SC_UNAUTHORIZED,
                            ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                            "Certificate chain validation failed");
                });
    }

    @Test
    public void shouldFailAuthentication_IfMdocResponseExpired() throws Exception {
        // Present an mDoc device response whose MSO validityInfo.validUntil lies in the past,
        // so verification fails the exp check. The container clock cannot be shifted, so the
        // forged validity window must be baked into the MSO itself.
        withAuthenticationProfile(AuthenticationProfileSamples.mdocPrimary(), (apiFlow, requestObject) -> {
            ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
            Map<String, Object> mdocClaims = Map.of(
                    MdocBaseTest.NAMESPACE,
                    Map.of(JsonWebToken.SUBJECT, TEST_USER_ID, OAuth2Constants.USERNAME, TEST_USER));
            String mdocToken = MdocBaseTest.buildMdocVpToken(
                    requestObject,
                    mdocClaims,
                    MdocBaseTest.DOC_TYPE,
                    now.minusMinutes(30),
                    now.minusMinutes(30),
                    now.minusMinutes(5));

            TestOpts opts = TestOpts.getDefault()
                    .setAuthContext(apiFlow.authContext())
                    .setCodeVerifier(apiFlow.codeVerifier())
                    .setShouldForceUnencryptedResponse(true);

            testFailingAuthenticationWithVPTokenMap(
                    Map.of(PRIMARY_CREDENTIAL_ID, mdocToken),
                    opts,
                    HttpStatus.SC_UNAUTHORIZED,
                    ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                    "Validity information verification failed");
        });
    }

    private String presentSdJwt(RequestObject requestObject) throws Exception {
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
        return sdJwtVPTestUtils.presentSdJwt(
                sdJwt, requestObject.getNonce(), requestObject.getClientId(), SdJwtVPTestUtils.getUserJwk());
    }

    private String presentMdoc(RequestObject requestObject, Map<String, Object> claims) throws Exception {
        return MdocBaseTest.buildMdocVpToken(requestObject, claims, MdocBaseTest.DOC_TYPE);
    }
}
