package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseUserAuthEndpointTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.protocol.oid4vc.model.PreAuthorizedCodeGrant;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * End-to-end tests for the OID4VCI "presentation during issuance" flow (OID4VCI §6) implemented by the
 * Authorization Challenge Endpoint. They cover the soll-flow of "OID4VCI Flow – VC Issuance":
 *
 * <ol>
 *   <li>the interaction-type negotiation (OID4VCI §6.2.2, {@code missing_interaction_type}),
 *   <li>the authorization-binding requirement (scope / authorization_details / issuer_state),
 *   <li>the {@code scope}-bound happy path (credential identity) including the forwarding protection
 *       ({@code expected_origins}, OID4VCI §6.2.1.1/§6.2.1.5) and the response/security semantics of the
 *       endpoint (wallet error response, holder-binding audience, empty response),
 *   <li>the {@code issuer_state}-bound challenge where the identity is the brokered SAFE user of the
 *       credential offer and the presented <strong>PID is matched against that user</strong> (the
 *       identity gate), issuing an {@code authorization_code} only after a successful match, and
 *   <li>the rejection of a presented PID that does not match the brokered user.
 * </ol>
 *
 * <p>The brokered credential offer is created through Keycloak's real OID4VCI
 * {@code create-credential-offer} endpoint (authenticated as {@code test-user}, exactly as the
 * Selfservice UI would), so the offer is genuinely bound to the SAFE user via {@code targetUserId}.
 * No test-only seeding is used. Both the login path (credential identity) and this issuance path
 * (session identity) run against the same shared realm.
 */
class PresentationDuringIssuanceTest extends OID4VPBaseUserAuthEndpointTest {

    /** Session-identity profile configured in the shared test realm (see test-realm.json). */
    private static final String STB_ISSUANCE_PROFILE_ID = "stb-issuance";

    /** VCT of the PID matched during issuance, as configured for the {@code stb-issuance} profile. */
    private static final String PID_VCT = "urn:eudi:pid:de:1";

    /**
     * {@code credential_configuration_id} of the credential being <em>issued</em> (the KMA / tax-advisor
     * VC that the offer is for). The PID is not issued by Keycloak; it is only presented by the wallet
     * during issuance and matched against the brokered user.
     */
    private static final String OFFERED_CREDENTIAL_CONFIG_ID = "kma_credential";

    /**
     * Registers the OID4VCI credential scope for the offered (KMA) credential at runtime via the Admin
     * API. This is done programmatically rather than in the realm import so the realm keeps Keycloak's
     * built-in default client scopes (e.g. {@code profile} → {@code preferred_username}); a bare
     * {@code clientScopes} block in a realm import would suppress those built-ins. The operation is
     * idempotent so it is safe with the reused (singleton) container.
     */
    @BeforeAll
    static void ensureOfferedCredentialScope() {
        var realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        boolean exists = realm.clientScopes().findAll().stream()
                .anyMatch(scope -> OFFERED_CREDENTIAL_CONFIG_ID.equals(scope.getName()));
        if (exists) {
            return;
        }

        ClientScopeRepresentation scope = new ClientScopeRepresentation();
        scope.setName(OFFERED_CREDENTIAL_CONFIG_ID);
        scope.setProtocol("oid4vc");
        scope.setAttributes(Map.of(
                "vc.credential_configuration_id", OFFERED_CREDENTIAL_CONFIG_ID,
                "vc.verifiable_credential_type", "https://credentials.example.com/kma_credential",
                "vc.format", "dc+sd-jwt",
                "vc.presentation_profile_id", STB_ISSUANCE_PROFILE_ID,
                "vc.requires_presentation", "true"));

        try (Response response = realm.clientScopes().create(scope)) {
            int status = response.getStatus();
            if (status != HttpStatus.SC_CREATED && status != HttpStatus.SC_CONFLICT) {
                throw new IllegalStateException("Failed to create offered credential scope: HTTP " + status);
            }
        }

        assignOfferedCredentialScopeToTestClient();
        grantOfferedCredentialToBrokeredUser();
    }

    /**
     * Assigns the offered (KMA) credential scope to the {@code test-app} client as an <em>optional</em> client
     * scope. The issuance gate ({@code PatchedOID4VCIssuerEndpoint#enforcePresentationDuringIssuance}) resolves
     * the credential configuration among the client's optional scopes ({@code client.getClientScopes(false)}),
     * so without this assignment the gate cannot see that the credential requires a presentation.
     */
    private static void assignOfferedCredentialScopeToTestClient() {
        var realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        String scopeId = realm.clientScopes().findAll().stream()
                .filter(scope -> OFFERED_CREDENTIAL_CONFIG_ID.equals(scope.getName()))
                .map(ClientScopeRepresentation::getId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Offered credential scope not found for assignment"));

        var clients = realm.clients().findByClientId(TEST_CLIENT_ID);
        if (clients.isEmpty()) {
            throw new IllegalStateException("Test client not found: " + TEST_CLIENT_ID);
        }
        realm.clients().get(clients.getFirst().getId()).addOptionalClientScope(scopeId);
    }

    /**
     * Grants the offered (KMA) verifiable credential to {@code test-user} via the Admin API. Since Keycloak now
     * validates on offer creation that the {@code target_user} actually holds the offered credential
     * ({@code OID4VCUtil.hasVerifiableCredential}), the brokered user must be granted the credential before a
     * credential offer can be created for it. The operation is idempotent (a duplicate grant returns HTTP 409),
     * so it is safe with the reused (singleton) container.
     */
    private static void grantOfferedCredentialToBrokeredUser() {
        String adminToken = keycloak.getKeycloakAdminClient().tokenManager().getAccessTokenString();
        String url = KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("admin/realms/{realm}/users/{userId}/vc/credentials")
                .build(TEST_REALM_NAME, TEST_USER_ID)
                .toString();

        HttpPost post = new HttpPost(url);
        post.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken);
        post.setEntity(new StringEntity(
                "{\"credentialScopeName\":\"" + OFFERED_CREDENTIAL_CONFIG_ID + "\"}", ContentType.APPLICATION_JSON));

        try (CloseableHttpClient client = HttpClientBuilder.create().build();
                CloseableHttpResponse response = client.execute(post)) {
            int status = response.getStatusLine().getStatusCode();
            // On success the admin endpoint returns the created representation as a POJO, which JAX-RS maps
            // to HTTP 200 (not a 201 Response); a duplicate grant yields HTTP 409. Either way the brokered
            // user holds the credential afterwards.
            if (status != HttpStatus.SC_OK && status != HttpStatus.SC_CONFLICT) {
                throw new IllegalStateException("Failed to grant offered credential to brokered user: HTTP " + status);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Failed to grant offered credential to brokered user", e);
        }
    }

    @Test
    @DisplayName("should reject the challenge with missing_interaction_type when presentation is unsupported")
    void should_RejectChallenge_When_InteractionTypeUnsupported() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        // No interaction_types_supported at all -> the server cannot fulfil the request (OID4VCI §6.2.2)
        var response = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
        var error = parseHttpResponse(response, OAuth2ErrorRepresentation.class);
        assertEquals(AuthorizationChallengeEndpoint.ERROR_MISSING_INTERACTION_TYPE, error.getError());
    }

    @Test
    @DisplayName("should reject the challenge when neither scope, authorization_details nor issuer_state is provided")
    void should_RejectChallenge_When_NoAuthorizationBindingProvided() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        var response = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
        var error = parseHttpResponse(response, OAuth2ErrorRepresentation.class);
        assertEquals(OAuthErrorException.INVALID_REQUEST, error.getError());
    }

    @Test
    @DisplayName("should issue authorization_code when the presented PID matches the brokered offer user")
    void should_IssueAuthorizationCode_When_PidMatchesBrokeredUser() throws Exception {
        // The credential offer binds the issuance to the brokered SAFE user (targetUserId = test-user).
        String issuerState = createRealCredentialOffer();

        // The presented PID carries the same identity as the brokered user (Tom Brady).
        var pidSdJwt = sdJwtVPTestUtils.requestPidSdJwtCredential(PID_VCT, "Tom", "Brady", "1990-01-01");

        var challenge = initiateIssuanceChallenge(issuerState);
        var resume = submitPresentation(pidSdJwt, challenge);

        // Identity gate passed (PID matched) -> authorization_code issued.
        assertEquals(HttpStatus.SC_OK, resume.getStatusLine().getStatusCode());
        assertNotNull(
                parseHttpResponse(resume, AuthorizationChallengeResponse.class).getAuthorizationCode());
    }

    @Test
    @DisplayName("should reject the presentation when the presented PID does not match the brokered offer user")
    void should_RejectPresentation_When_PidDoesNotMatchBrokeredUser() throws Exception {
        String issuerState = createRealCredentialOffer();

        // The presented PID belongs to a different person than the brokered user (family_name mismatch).
        var pidSdJwt = sdJwtVPTestUtils.requestPidSdJwtCredential(PID_VCT, "Tom", "Manning", "1990-01-01");

        var challenge = initiateIssuanceChallenge(issuerState);
        var resume = submitPresentation(pidSdJwt, challenge);

        // Identity gate failed (PID did not match) -> the presentation is rejected (401), no code issued.
        assertEquals(HttpStatus.SC_UNAUTHORIZED, resume.getStatusLine().getStatusCode());
    }

    @Test
    @DisplayName("should refuse issuance via the pre-authorized code flow for a presentation-gated credential")
    void should_RefuseIssuance_When_PreAuthorizedCodeFlowForGatedCredential() throws Exception {
        String preAuthorizedCode = createRealPreAuthorizedCredentialOffer();

        String accessToken = redeemPreAuthorizedCode(preAuthorizedCode);

        HttpResponse credentialResponse = requestOfferedCredential(accessToken);
        assertEquals(
                HttpStatus.SC_BAD_REQUEST, credentialResponse.getStatusLine().getStatusCode());
        var error = parseHttpResponse(credentialResponse, OAuth2ErrorRepresentation.class);
        assertEquals("invalid_credential_request", error.getError());
    }

    @Test
    @DisplayName("should re-challenge without a fresh request while cross-device polling before presentation")
    void should_ReChallenge_When_CrossDevicePollingBeforePresentation() throws Exception {
        var sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        // 1. Initiate -> 401 insufficient_authorization with the inline OpenID4VP request and an auth_session.
        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);
        assertNotNull(challenge.getAuthSession());
        assertNotNull(challenge.getOpenid4vpRequest());

        // 2. Cross-device poll before presenting (auth_session only) -> 401 re-challenge WITHOUT a fresh request.
        var poll = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession())));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, poll.getStatusLine().getStatusCode());
        var pollBody = parseHttpResponse(poll, AuthorizationChallengeResponse.class);
        assertEquals(AuthorizationChallengeEndpoint.ERROR_INSUFFICIENT_AUTHORIZATION, pollBody.getError());
        assertEquals(
                AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION,
                pollBody.getInteractionTypeRequired());
        assertEquals(challenge.getAuthSession(), pollBody.getAuthSession());
        // §6.2.1.4: no new nonce/request is emitted; the wallet keeps using the original inline request.
        assertNull(pollBody.getOpenid4vpRequest());

        // 3. Present, then poll again -> the completed challenge yields the authorization_code.
        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);
        var openid4vpResponse = buildOpenid4vpResponseJson(sdJwt, requestObject);
        var submit = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, openid4vpResponse)));
        assertEquals(HttpStatus.SC_OK, submit.getStatusLine().getStatusCode());

        var finalPoll = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession())));
        assertEquals(HttpStatus.SC_OK, finalPoll.getStatusLine().getStatusCode());
        assertNotNull(parseHttpResponse(finalPoll, AuthorizationChallengeResponse.class)
                .getAuthorizationCode());
    }

    @Test
    @DisplayName("should reject polling/resume when the auth_session expired or was evicted mid-interactive")
    void should_RejectResume_When_AuthSessionExpiredMidInteractive() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        // Start a real challenge to obtain a genuinely-formatted auth_session handle.
        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        String authSession = parseHttpResponse(initiate, AuthorizationChallengeResponse.class)
                .getAuthSession();
        assertNotNull(authSession);

        // Simulate the session expiring/being evicted mid-interactive: keep the valid "root.tab" shape but
        // point the root segment at a session that no longer exists. The handle can no longer be resolved.
        String expiredAuthSession = UUID.randomUUID() + authSession.substring(authSession.indexOf('.'));

        var resume = postChallenge(
                List.of(new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, expiredAuthSession)));

        // The wallet's poll after expiry is rejected with a defined error, not silently accepted.
        assertEquals(HttpStatus.SC_BAD_REQUEST, resume.getStatusLine().getStatusCode());
        var error = parseHttpResponse(resume, OAuth2ErrorRepresentation.class);
        assertEquals(OAuthErrorException.INVALID_REQUEST, error.getError());
    }

    @Test
    @DisplayName("should issue authorization_code for the scope-bound (credential identity) presentation")
    void should_IssueAuthorizationCode_When_PresentationSucceeds() throws Exception {
        var sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        // 1. Initiate challenge -> 401 insufficient_authorization with the signed OpenID4VP request
        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);
        assertEquals(AuthorizationChallengeEndpoint.ERROR_INSUFFICIENT_AUTHORIZATION, challenge.getError());
        assertNotNull(challenge.getAuthSession());

        // 2. Read the inline signed request object and submit the OpenID4VP response (response_mode=ia_post)
        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);

        // §6.2.1.1/§6.2.1.5: request is bound to the challenge endpoint origin to prevent forwarding
        var realmUri = URI.create(getTestRealmEndpoint());
        var challengeOrigin = realmUri.getScheme() + "://" + realmUri.getAuthority();
        assertEquals(List.of(challengeOrigin), requestObject.getExpectedOrigins());

        var openid4vpResponse = buildOpenid4vpResponseJson(sdJwt, requestObject);

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, openid4vpResponse)));

        // 3. -> 200 with authorization_code
        assertEquals(HttpStatus.SC_OK, resume.getStatusLine().getStatusCode());
        assertNotNull(
                parseHttpResponse(resume, AuthorizationChallengeResponse.class).getAuthorizationCode());
    }

    @Test
    @DisplayName("should return error response when wallet submits an OpenID4VP error (no authorization_code)")
    void should_ReturnError_When_WalletSubmitsErrorResponse() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);

        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);

        // Wallet submits an OpenID4VP Authorization Error Response (OID4VCI §6.2.1.1)
        var errorResponse = String.format(
                "{\"error\":\"%s\",\"error_description\":\"User declined\",\"state\":\"%s\"}",
                OAuthErrorException.ACCESS_DENIED, requestObject.getState());

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, errorResponse)));

        // -> 400 error response, no authorization_code (not an empty 200)
        assertEquals(HttpStatus.SC_BAD_REQUEST, resume.getStatusLine().getStatusCode());
        var error = parseHttpResponse(resume, OAuth2ErrorRepresentation.class);
        assertEquals(OAuthErrorException.ACCESS_DENIED, error.getError());
    }

    @Test
    @DisplayName("should reject presentation whose holder-binding audience is not bound to the challenge endpoint")
    void should_RejectPresentation_When_AudienceNotBoundToChallengeEndpoint() throws Exception {
        var sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER);
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);

        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);

        // Present with a Key Binding JWT audience that is NOT the expected verifier (forwarding attempt)
        var tamperedResponse = buildOpenid4vpResponseJson(sdJwt, requestObject, "https://attacker.example.com");

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, tamperedResponse)));

        // -> rejected with 401 (invalid presentation / holder binding), no authorization_code issued
        assertEquals(HttpStatus.SC_UNAUTHORIZED, resume.getStatusLine().getStatusCode());
    }

    @Test
    @DisplayName("should reject openid4vp_response that contains neither vp_token, response nor error")
    void should_RejectEmptyResponse_When_NoVpTokenResponseOrError() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));
        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);

        // openid4vp_response with only a state value (no vp_token, response or error)
        var emptyResponse = "{\"state\":\"irrelevant\"}";

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, emptyResponse)));

        assertEquals(HttpStatus.SC_BAD_REQUEST, resume.getStatusLine().getStatusCode());
        var error = parseHttpResponse(resume, OAuth2ErrorRepresentation.class);
        assertEquals(OAuthErrorException.INVALID_REQUEST, error.getError());
    }

    /**
     * Initiates the {@code issuer_state}-bound authorization challenge for the session-identity profile
     * and asserts the {@code 401 insufficient_authorization} with the inline OpenID4VP request.
     */
    private AuthorizationChallengeResponse initiateIssuanceChallenge(String issuerState) throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        var initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.PROFILE_ID_PARAM, STB_ISSUANCE_PROFILE_ID),
                new BasicNameValuePair(OAuth2Constants.ISSUER_STATE, issuerState),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        var challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);
        assertEquals(AuthorizationChallengeEndpoint.ERROR_INSUFFICIENT_AUTHORIZATION, challenge.getError());
        assertNotNull(challenge.getAuthSession());
        return challenge;
    }

    /**
     * Submits the wallet's OpenID4VP response (response_mode=ia_post) for the given challenge.
     */
    private HttpResponse submitPresentation(String pidSdJwt, AuthorizationChallengeResponse challenge)
            throws Exception {
        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);
        var openid4vpResponse = buildOpenid4vpResponseJson(pidSdJwt, requestObject);

        return postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, openid4vpResponse)));
    }

    /**
     * Creates a real OID4VCI credential offer bound to {@code test-user} through Keycloak's own
     * {@code create-credential-offer} endpoint (authorization_code grant) and returns the resulting
     * {@code issuer_state}. This is the exact production path the Selfservice UI uses.
     *
     * <ol>
     *   <li>authenticate as {@code test-user} (real login) and obtain an access token,
     *   <li>{@code GET create-credential-offer} (authenticated) → credential offer URI (issuer + nonce),
     *   <li>{@code GET credential-offer/{nonce}} → credential offer with the authorization_code grant.
     * </ol>
     */
    private String createRealCredentialOffer() throws Exception {
        JsonNode offer = fetchCredentialOffer(false);
        JsonNode issuerStateNode =
                offer.path("grants").path(OAuth2Constants.AUTHORIZATION_CODE).path(OAuth2Constants.ISSUER_STATE);
        assertNotNull(issuerStateNode, "credential offer must carry an authorization_code grant issuer_state");
        String issuerState = issuerStateNode.asText(null);
        assertNotNull(issuerState, "issuer_state must be present in the credential offer");
        return issuerState;
    }

    /**
     * Creates a real <em>pre-authorized</em> OID4VCI credential offer bound to {@code test-user} through
     * Keycloak's own {@code create-credential-offer} endpoint and returns the {@code pre-authorized_code}
     * from the resulting credential offer.
     */
    private String createRealPreAuthorizedCredentialOffer() throws Exception {
        JsonNode offer = fetchCredentialOffer(true);
        JsonNode preAuthCodeNode = offer.path("grants")
                .path(PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE)
                .path(PreAuthorizedCodeGrant.CODE_REQUEST_PARAM);
        assertNotNull(preAuthCodeNode, "credential offer must carry a pre-authorized_code grant");
        String preAuthorizedCode = preAuthCodeNode.asText(null);
        assertNotNull(preAuthorizedCode, "pre-authorized_code must be present in the credential offer");
        return preAuthorizedCode;
    }

    /**
     * Authenticates as {@code test-user}, creates a credential offer for the offered (gated) credential via
     * {@code create-credential-offer} and dereferences it to the full credential offer JSON.
     *
     * @param preAuthorized whether to request a {@code pre-authorized_code} grant instead of the
     *                      {@code authorization_code} grant
     */
    private JsonNode fetchCredentialOffer(boolean preAuthorized) throws Exception {
        String authCode = getFreshAuthorizationCode();
        String accessToken = requestAccessToken(authCode, true);

        String createOfferUrl = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/create-credential-offer")
                .queryParam("credential_configuration_id", OFFERED_CREDENTIAL_CONFIG_ID)
                .queryParam("pre_authorized", Boolean.toString(preAuthorized))
                .queryParam("target_user", TEST_USER)
                .build()
                .toString();
        HttpGet createOfferReq = new HttpGet(createOfferUrl);
        createOfferReq.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        HttpResponse createOfferResp = httpClient.execute(createOfferReq);
        assertEquals(HttpStatus.SC_OK, createOfferResp.getStatusLine().getStatusCode());
        JsonNode offerUri = readJson(createOfferResp);
        String issuer = offerUri.get("issuer").asText();
        String nonce = offerUri.get("nonce").asText();

        HttpResponse offerResp = httpClient.execute(new HttpGet(issuer + "/" + nonce));
        assertEquals(HttpStatus.SC_OK, offerResp.getStatusLine().getStatusCode());
        return readJson(offerResp);
    }

    /**
     * Redeems a {@code pre-authorized_code} at the token endpoint and returns the issued access token
     * (bound to the credential endpoint audience).
     */
    private String redeemPreAuthorizedCode(String preAuthorizedCode) throws Exception {
        var params = getDefaultHttpParams();
        params.add(new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE));
        params.add(new BasicNameValuePair(PreAuthorizedCodeGrant.CODE_REQUEST_PARAM, preAuthorizedCode));

        HttpPost tokenReq = new HttpPost(getTestTokenEndpoint());
        tokenReq.setEntity(new UrlEncodedFormEntity(params));
        HttpResponse tokenResp = httpClient.execute(tokenReq);
        assertEquals(HttpStatus.SC_OK, tokenResp.getStatusLine().getStatusCode());
        JsonNode token = readJson(tokenResp);
        String accessToken = token.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
        assertNotNull(accessToken, "pre-authorized code redemption must yield an access token");
        return accessToken;
    }

    /**
     * Requests the offered (presentation-gated) credential at the OID4VCI credential endpoint using the
     * given access token.
     */
    private HttpResponse requestOfferedCredential(String accessToken) throws Exception {
        String credentialUrl = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/credential")
                .build()
                .toString();
        HttpPost credentialReq = new HttpPost(credentialUrl);
        credentialReq.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        credentialReq.setEntity(new StringEntity(
                "{\"credential_configuration_id\":\"" + OFFERED_CREDENTIAL_CONFIG_ID + "\"}",
                ContentType.APPLICATION_JSON));
        return httpClient.execute(credentialReq);
    }

    private JsonNode readJson(HttpResponse response) throws IOException {
        String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return JsonSerialization.mapper.readTree(payload);
    }

    private HttpResponse postChallenge(List<BasicNameValuePair> form) throws Exception {
        var url = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path(AuthorizationChallengeEndpointFactory.PROVIDER_ID)
                .build()
                .toString();
        var post = new HttpPost(url);
        post.setEntity(new UrlEncodedFormEntity(form));
        return httpClient.execute(post);
    }
}
