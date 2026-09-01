package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata.OID4VCIssuerMetadataProvider.ATTR_PRESENTATION_DURING_ISSUANCE;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.PresentationDuringIssuanceBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.PresentationDuringIssuanceMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ProcessingError;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.ResponseToWallet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.protocol.oid4vc.model.ErrorType;
import org.keycloak.protocol.oid4vc.model.IssuerState;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * End-to-end tests for nested presentation during issuance.
 *
 * <p>These tests exercise the complete path: a normal OIDC authorization request is gated by a
 * nested OpenID4VP presentation, the resulting OIDC code is exchanged for an access token, and
 * the access token is used to obtain the gated credential.
 */
class NestedPresentationDuringIssuanceTest extends PresentationDuringIssuanceBaseTest {

    private static final String CREDENTIAL_IDENTITY_CONFIG_ID = "nested_gated_credential";
    private static final String INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID = "ia_gated_credential";
    private static final String SESSION_IDENTITY_CONFIG_ID = "nested_session_gated_credential";
    private static final String UNGATED_CREDENTIAL_CONFIG_ID = "nested_ungated_credential";
    private static final String MISSING_PROFILE_CONFIG_ID = "nested_missing_profile_credential";
    private static final String SESSION_PROFILE_ID = "stb-issuance";
    private static final String PID_VCT = "urn:eudi:pid:de:1";
    private static final String OPENID4VP_SCHEME = "openid4vp://";

    private String logsAtTestStart;

    @BeforeEach
    void captureLogsAtTestStart() {
        logsAtTestStart = keycloak.getLogs();
    }

    @BeforeAll
    static void ensureNestedCredentialScopes() {
        // Configure one credential for each nested-flow binding and keep an ungated control credential.
        var realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        assertPresentationDuringIssuanceEnabled(realm);
        ensureCredentialScope(
                realm,
                CREDENTIAL_IDENTITY_CONFIG_ID,
                CREDENTIAL_TYPES_CONFIG_DEFAULT,
                PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW,
                AuthenticationProfile.DEFAULT_PROFILE_ID);
        ensureCredentialScope(
                realm,
                SESSION_IDENTITY_CONFIG_ID,
                CREDENTIAL_TYPES_CONFIG_DEFAULT,
                PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW,
                SESSION_PROFILE_ID);
        ensureCredentialScope(realm, UNGATED_CREDENTIAL_CONFIG_ID, CREDENTIAL_TYPES_CONFIG_DEFAULT, null, null);
        ensureCredentialScope(
                realm,
                MISSING_PROFILE_CONFIG_ID,
                CREDENTIAL_TYPES_CONFIG_DEFAULT,
                PresentationDuringIssuanceMode.NESTED_OID4VP_FLOW,
                null);
        ensureCredentialScope(
                realm,
                INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID,
                CREDENTIAL_TYPES_CONFIG_DEFAULT,
                PresentationDuringIssuanceMode.INTERACTIVE_AUTHORIZATION,
                AuthenticationProfile.DEFAULT_PROFILE_ID);
        grantCredentialToTestUser(CREDENTIAL_IDENTITY_CONFIG_ID);
        grantCredentialToTestUser(SESSION_IDENTITY_CONFIG_ID);
        grantCredentialToTestUser(UNGATED_CREDENTIAL_CONFIG_ID);
        grantCredentialToTestUser(MISSING_PROFILE_CONFIG_ID);
        grantCredentialToTestUser(INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID);
    }

    @Test
    @DisplayName("should complete nested session-identity authorization using issuer_state")
    void shouldCompleteSessionIdentityAuthorizationUsingIssuerState() throws Exception {
        String issuerState = createAuthorizationCodeCredentialOffer(SESSION_IDENTITY_CONFIG_ID);
        String pid = sdJwtVPTestUtils.requestPidSdJwtCredential(PID_VCT, "Tom", "Brady", "1990-01-01");

        String authCode = completeNestedAuthorization(SESSION_IDENTITY_CONFIG_ID, null, issuerState, pid);
        assertCredentialIssued(authCode);
    }

    @Test
    @DisplayName("should preserve nested issuance authorization through PAR and request_uri processing")
    void shouldCompleteNestedAuthorizationThroughPar() throws Exception {
        String issuerState = createAuthorizationCodeCredentialOffer(CREDENTIAL_IDENTITY_CONFIG_ID);
        String requestUri = submitPar(issuerState);

        String authEndpoint = new URIBuilder(getAuthEndpointURI())
                .addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .addParameter(OIDCLoginProtocol.REQUEST_URI_PARAM, requestUri)
                .build()
                .toString();

        String identityCredential = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
        String authCode = completeNestedAuthorization(authEndpoint, identityCredential);
        assertCredentialIssued(authCode);
    }

    @Test
    @DisplayName("should issue a credential-identity credential after nested presentation using authorization_details")
    void shouldIssueCredentialUsingAuthorizationDetails() throws Exception {
        String identityCredential = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
        String authorizationDetails = authorizationDetails(CREDENTIAL_IDENTITY_CONFIG_ID);

        String authCode = completeNestedAuthorization(
                CREDENTIAL_IDENTITY_CONFIG_ID, authorizationDetails, null, identityCredential);
        assertCredentialIssued(authCode);
    }

    @Test
    @DisplayName("should issue a credential-identity credential after nested presentation using scope")
    void shouldIssueCredentialUsingScope() throws Exception {
        String identityCredential = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        String authCode = completeNestedAuthorization(CREDENTIAL_IDENTITY_CONFIG_ID, null, null, identityCredential);
        assertCredentialIssued(authCode);
    }

    @Test
    @DisplayName("should issue an ungated credential without a presentation")
    void shouldIssueUngatedCredentialWithoutPresentation() throws Exception {
        // A pre-authorized token for an ungated credential must remain usable without an OID4VP marker.
        JsonNode offer = createCredentialOffer(UNGATED_CREDENTIAL_CONFIG_ID, true);
        String accessToken = requestPreAuthorizedAccessToken(offer);
        JsonNode tokenPayload = decodeJwtPayload(accessToken);
        String credentialIdentifier = tokenPayload
                .path(OAuth2Constants.AUTHORIZATION_DETAILS)
                .path(0)
                .path("credential_identifiers")
                .path(0)
                .asText(null);
        assertNotNull(credentialIdentifier, "The access token must advertise a credential identifier");

        HttpResponse response = requestCredentialWithIdentifier(accessToken, credentialIdentifier);
        String body = EntityUtils.toString(response.getEntity());
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode(), body);
        JsonNode credentialResponse = JsonSerialization.mapper.readTree(body);
        assertTrue(credentialResponse.has("credentials"), "An ungated credential must be returned: " + body);
    }

    @Test
    @DisplayName("should not start nested presentation for an ungated authorization_details request")
    void shouldNotGateUngatedCredentialUsingAuthorizationDetails() throws Exception {
        Connection.Response response = requestAuthorizationPage(
                buildAuthorizationEndpoint(null, authorizationDetails(UNGATED_CREDENTIAL_CONFIG_ID), null));

        assertEquals(HttpStatus.SC_OK, response.statusCode(), "Unexpected authorization response");
        assertTrue(
                response.parse().select("a[href^=openid4vp://]").isEmpty(),
                "An ungated authorization_details request must not start nested presentation");
    }

    @Test
    @DisplayName("should not start nested presentation for an unknown issuer_state")
    void shouldNotGateCredentialUsingUnknownIssuerState() throws Exception {
        String unknownIssuerState = new IssuerState()
                .setCredentialsOfferId("unknown-offer-" + UUID.randomUUID())
                .encodeToString();

        Connection.Response response =
                requestAuthorizationPage(buildAuthorizationEndpoint(null, null, unknownIssuerState));

        assertEquals(HttpStatus.SC_OK, response.statusCode(), "Unexpected authorization response");
        assertTrue(
                response.parse().select("a[href^=openid4vp://]").isEmpty(),
                "An unknown issuer_state must not start nested presentation");
    }

    @Test
    @DisplayName("should ignore malformed issuer_state without starting nested presentation")
    void shouldIgnoreMalformedIssuerState() throws Exception {
        Connection.Response response =
                requestAuthorizationPage(buildAuthorizationEndpoint(null, null, "not-a-valid-issuer-state"));

        assertEquals(HttpStatus.SC_OK, response.statusCode());
        assertTrue(
                response.parse().select("a[href^=openid4vp://]").isEmpty(),
                "A malformed issuer_state must not start nested presentation");
    }

    @Test
    @DisplayName("should not start nested presentation when presentation during issuance is disabled")
    void shouldNotStartNestedPresentationWhenRealmFeatureDisabled() throws Exception {
        RealmResource realm = getActiveTestRealmResource();
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> attributes =
                new HashMap<>(Optional.ofNullable(rep.getAttributes()).orElseGet(Map::of));
        String original = attributes.get(ATTR_PRESENTATION_DURING_ISSUANCE);

        try {
            attributes.put(ATTR_PRESENTATION_DURING_ISSUANCE, "false");
            rep.setAttributes(attributes);
            realm.update(rep);

            // The gated credential binding remains in place, but the disabled realm feature must
            // keep the login flow ordinary instead of starting a nested presentation.
            Connection.Response response =
                    requestAuthorizationPage(buildAuthorizationEndpoint(CREDENTIAL_IDENTITY_CONFIG_ID, null, null));

            assertEquals(HttpStatus.SC_OK, response.statusCode(), "Unexpected authorization response");
            assertTrue(
                    response.parse().select("a[href^=openid4vp://]").isEmpty(),
                    "Nested presentation must not start while the realm feature is disabled");
        } finally {
            if (original == null) {
                attributes.remove(ATTR_PRESENTATION_DURING_ISSUANCE);
            } else {
                attributes.put(ATTR_PRESENTATION_DURING_ISSUANCE, original);
            }
            rep.setAttributes(attributes);
            realm.update(rep);
        }
    }

    @Test
    @DisplayName("should report a configuration error when nested presentation profile is missing")
    void shouldReportConfigurationErrorWhenNestedPresentationProfileIsMissing() throws Exception {
        Connection.Response response =
                requestAuthorizationPage(buildAuthorizationEndpoint(MISSING_PROFILE_CONFIG_ID, null, null));

        assertEquals(HttpStatus.SC_OK, response.statusCode(), "Unexpected authorization response");
        assertTrue(response.body().contains("Unable to continue with the wallet presentation"));
        assertTrue(response.parse().select("a[href^=openid4vp://]").isEmpty());
    }

    @Test
    @DisplayName("should reject a nested presentation belonging to a different user")
    void shouldRejectMismatchedIdentityInNestedFlow() throws Exception {
        // The credential subject is unknown/mismatched.
        String identityCredential =
                sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, "unknown-user-id", TEST_USER);
        Connection.Response initial =
                startNestedAuthorization(buildAuthorizationEndpoint(CREDENTIAL_IDENTITY_CONFIG_ID, null, null));
        String location = nestedLink(initial);
        RequestObject requestObject = resolveRequestObject(location);

        HttpResponse response = sendAuthorizationResponse(
                identityCredential,
                requestObject,
                TestOpts.getDefault()
                        .setAuthContext(new AuthorizationContext().setAuthorizationRequest(location))
                        .setShouldRetrieveAccessToken(false));

        // The nested presentation fails before the parent OIDC authorization can complete.
        assertErrorResponse(
                response,
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "User with presented OID4VP credential is unknown");
    }

    @Test
    @DisplayName("should use issuer_state credential configuration over conflicting authorization details and scope")
    void shouldUseIssuerStateCredentialConfigurationWhenRequestBindingsConflict() throws Exception {
        // issuer_state must win over wallet-supplied scope and authorization_details values.
        String issuerState = createAuthorizationCodeCredentialOffer(SESSION_IDENTITY_CONFIG_ID);
        Connection.Response initial = startNestedAuthorization(buildAuthorizationEndpoint(
                UNGATED_CREDENTIAL_CONFIG_ID, authorizationDetails(UNGATED_CREDENTIAL_CONFIG_ID), issuerState));
        assertTrue(nestedLink(initial).startsWith(OPENID4VP_SCHEME));
    }

    @Test
    @DisplayName("should not issue a nested-only credential after ordinary OID4VP login")
    void shouldNotIssueNestedCredentialAfterOrdinaryOid4vpLogin() throws Exception {
        // Request an optional credential scope whose policy allows interactive authorization rather
        // than nested OID4VP. The scope is therefore available for token-request authorization_details,
        // but does not turn this ordinary same-device login into a nested PDI flow.
        FormData formData = getFreshOid4vpFormActionUrl(false, INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID);
        String identityCredential = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);

        TestFlowData flowData = testSuccessfulAuthenticationVerbose(
                identityCredential,
                TestOpts.getDefault()
                        .setAuthContext(formData.authContextSameDevice())
                        .setCodeVerifier(formData.oid4vpCodeVerifier())
                        .setOidcPkceCodeVerifier(formData.oidcPkceCodeVerifier())
                        .setShouldRetrieveAccessToken(false));

        try (CloseableHttpClient client = HttpClientBuilder.create()
                .setDefaultCookieStore(formData.cookieStore())
                .disableRedirectHandling()
                .build()) {
            // Resume the parent OIDC transaction and exchange its authorization code.
            HttpResponse callbackResponse =
                    client.execute(new HttpGet(flowData.responseToWallet().getRedirectUri()));
            String loginActionUrl = captureNextRedirect(callbackResponse);
            String authorizationCode = extractAuthCodeInRedirect(client.execute(new HttpGet(loginActionUrl)));
            String accessToken = requestAccessToken(authorizationCode, true);

            // The session carries no verified-presentation marker: the gate must refuse issuance.
            HttpResponse credentialResponse =
                    requestCredentialWithConfigurationId(accessToken, INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID);
            assertErrorResponse(
                    credentialResponse,
                    HttpStatus.SC_BAD_REQUEST,
                    ErrorType.INVALID_CREDENTIAL_REQUEST.getValue(),
                    "Credential '%s' requires a verified presentation during issuance"
                            .formatted(INTERACTIVE_GATED_CREDENTIAL_CONFIG_ID));
        }
    }

    @Test
    @DisplayName("should not carry nested presentation authorization into a separate pre-authorized transaction")
    void shouldIsolateNestedPresentationAuthorizationBetweenTransactions() throws Exception {
        // Complete one nested transaction, then use a separate pre-authorized transaction.
        String identityCredential = sdJwtVPTestUtils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
        completeNestedAuthorization(CREDENTIAL_IDENTITY_CONFIG_ID, null, null, identityCredential);

        JsonNode offer = createCredentialOffer(SESSION_IDENTITY_CONFIG_ID, true);
        String accessToken = requestPreAuthorizedAccessToken(offer);
        HttpResponse credentialResponse = requestCredentialWithConfigurationId(accessToken, SESSION_IDENTITY_CONFIG_ID);

        // Presentation authorization must not leak between access-token transactions.
        assertErrorResponse(
                credentialResponse,
                HttpStatus.SC_BAD_REQUEST,
                ErrorType.INVALID_CREDENTIAL_REQUEST.getValue(),
                "Credential '%s' requires a verified presentation during issuance"
                        .formatted(SESSION_IDENTITY_CONFIG_ID));
    }

    @Test
    @DisplayName("should reject session-identity nested presentation when issuer_state is absent")
    void shouldRejectSessionIdentityWithoutIssuerState() throws Exception {
        // A session-identity profile cannot resolve its subject without the offer's issuer_state.
        String pid = sdJwtVPTestUtils.requestPidSdJwtCredential(PID_VCT, "Tom", "Brady", "1990-01-01");

        String authEndpoint = buildAuthorizationEndpoint(SESSION_IDENTITY_CONFIG_ID, null, null);
        Connection.Response initial = startNestedAuthorization(authEndpoint);
        String location = nestedLink(initial);
        var response = sendAuthorizationResponse(
                pid,
                resolveRequestObject(location),
                TestOpts.getDefault()
                        .setAuthContext(new AuthorizationContext().setAuthorizationRequest(location))
                        .setShouldRetrieveAccessToken(false));

        // Reject the presentation rather than authenticating an unbound user.
        assertErrorResponse(
                response,
                HttpStatus.SC_UNAUTHORIZED,
                ProcessingError.VP_TOKEN_AUTH_ERROR.getErrorString(),
                "Invalid OID4VP credential presentation: Missing session-bound subject user");
    }

    @Test
    @DisplayName("should reject multiple openid_credential authorization details")
    void shouldRejectMultipleCredentialAuthorizationDetails() throws Exception {
        // Nested issuance supports exactly one credential configuration per authorization request.
        String details = authorizationDetails(CREDENTIAL_IDENTITY_CONFIG_ID, SESSION_IDENTITY_CONFIG_ID);
        String authEndpoint = buildAuthorizationEndpoint(null, details, null);

        Connection.Response response = requestAuthorizationPage(authEndpoint);
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.statusCode());
        assertTrue(response.body().contains("An internal server error has occurred"));
        assertLogContains("Credential endpoint does not support issuing multiple credential types");
    }

    private String buildAuthorizationEndpoint(String scope, String authorizationDetails, String issuerState)
            throws Exception {
        // Build the parent OIDC request while allowing tests to vary its credential binding.
        URIBuilder builder =
                new URIBuilder(getAuthEndpointURI()).addParameter(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID);
        for (BasicNameValuePair param : baseAuthorizationRequestParams(issuerState, scope)) {
            builder.addParameter(param.getName(), param.getValue());
        }

        if (authorizationDetails != null) {
            builder.addParameter(OAuth2Constants.AUTHORIZATION_DETAILS, authorizationDetails);
        }

        return builder.build().toString();
    }

    private String submitPar(String issuerState) throws Exception {
        String parEndpoint = new URIBuilder(getTestRealmEndpoint() + "/protocol/openid-connect/ext/par/request")
                .build()
                .toString();

        var params = new ArrayList<>(getDefaultHttpParams());
        params.addAll(baseAuthorizationRequestParams(issuerState, CREDENTIAL_IDENTITY_CONFIG_ID));

        HttpPost request = new HttpPost(parEndpoint);
        request.setEntity(new UrlEncodedFormEntity(params));
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatusLine().getStatusCode());
            JsonNode body = JsonSerialization.mapper.readTree(EntityUtils.toString(response.getEntity()));
            String requestUri = body.path("request_uri").asText(null);
            assertNotNull(requestUri, "PAR response must contain request_uri");
            return requestUri;
        }
    }

    /**
     * The authorization parameters shared by the direct authorize endpoint and its PAR variant,
     * excluding the client authentication parameters each transport adds itself.
     */
    private List<BasicNameValuePair> baseAuthorizationRequestParams(String issuerState, String scope) {
        var params = new ArrayList<BasicNameValuePair>();
        params.add(new BasicNameValuePair(OAuth2Constants.RESPONSE_TYPE, OAuth2Constants.CODE));
        params.add(new BasicNameValuePair(OAuth2Constants.REDIRECT_URI, TEST_CLIENT_REDIRECT_URI));
        params.add(new BasicNameValuePair(
                OAuth2Constants.SCOPE,
                scope == null ? OAuth2Constants.SCOPE_OPENID : OAuth2Constants.SCOPE_OPENID + " " + scope));
        if (issuerState != null) {
            params.add(new BasicNameValuePair(OAuth2Constants.ISSUER_STATE, issuerState));
        }
        return params;
    }

    private String authorizationDetails(String... configurationIds) {
        // Encode the same authorization_details shape wallets send to the OIDC endpoint.
        String template = """
           { "type": "openid_credential", "credential_configuration_id": "%s", "locations":["%s"] }
        """;

        String location = getTestRealmEndpoint();
        String details = Arrays.stream(configurationIds)
                .map(id -> template.formatted(id, location).strip())
                .collect(Collectors.joining(","));

        return "[%s]".formatted(details);
    }

    private Connection.Response startNestedAuthorization(String authEndpoint) throws Exception {
        // The initial page must be the nested presentation prompt, not an error or redirect.
        Connection.Response initial = requestAuthorizationPage(authEndpoint);
        assertEquals(
                HttpStatus.SC_OK,
                initial.statusCode(),
                "Unexpected authorization response: " + initial.statusCode() + " "
                        + initial.header("Location") + " "
                        + initial.body().replaceAll("\\s+", " "));
        return initial;
    }

    private Connection.Response requestAuthorizationPage(String authEndpoint) throws Exception {
        return requestAuthorizationPage(authEndpoint, new HashMap<>());
    }

    private Connection.Response requestAuthorizationPage(String authEndpoint, Map<String, String> cookieSink)
            throws Exception {
        // Follow redirects hop-by-hop while accumulating session cookies (e.g. across the PAR
        // request_uri hop), keeping HTTP errors visible so callers can assert the returned response.
        String url = authEndpoint;
        for (int hop = 0; hop < 5; hop++) {
            Connection.Response response = Jsoup.connect(url)
                    .method(Connection.Method.GET)
                    .header(HttpHeaders.ACCEPT, ContentType.TEXT_HTML.getMimeType())
                    .cookies(cookieSink)
                    .followRedirects(false)
                    .ignoreContentType(true)
                    .ignoreHttpErrors(true)
                    .execute();
            cookieSink.putAll(response.cookies());
            if (response.statusCode() < HttpStatus.SC_MULTIPLE_CHOICES
                    || response.statusCode() >= HttpStatus.SC_BAD_REQUEST) {
                return response;
            }
            String location = response.header(HttpHeaders.LOCATION);
            assertNotNull(location, "Redirect response without Location header");
            url = URI.create(url).resolve(location).toString();
        }
        throw new IllegalStateException("Too many redirects fetching authorization page: " + authEndpoint);
    }

    private String nestedLink(Connection.Response response) throws Exception {
        // Find the wallet deep link among the surrounding Keycloak theme links.
        var document = response.parse();
        String location = document.select("a").stream()
                .map(element -> element.attr("href"))
                .filter(href -> href.startsWith(OPENID4VP_SCHEME))
                .findFirst()
                .orElse(null);
        assertNotNull(location, "Nested authorization must render a same-device OpenID4VP link");
        return location;
    }

    private String completeNestedAuthorization(
            String scope, String authorizationDetails, String issuerState, String presentedCredential)
            throws Exception {
        // Drive the nested presentation, callback, and parent OIDC authorization-code steps.
        return completeNestedAuthorization(
                buildAuthorizationEndpoint(scope, authorizationDetails, issuerState), presentedCredential);
    }

    private String completeNestedAuthorization(String authEndpoint, String presentedCredential) throws Exception {
        Map<String, String> browserCookies = new HashMap<>();
        Connection.Response initial = requestAuthorizationPage(authEndpoint, browserCookies);
        String location = nestedLink(initial);
        BasicCookieStore cookieStore = convertCookiesMapToStore(browserCookies);

        TestFlowData flowData = testSuccessfulAuthenticationVerbose(
                presentedCredential,
                TestOpts.getDefault()
                        .setAuthContext(new AuthorizationContext().setAuthorizationRequest(location))
                        .setShouldRetrieveAccessToken(false));
        ResponseToWallet responseToWallet = flowData.responseToWallet();
        assertNotNull(responseToWallet.getRedirectUri(), "Nested presentation should return an OIDC callback URI");

        try (CloseableHttpClient client = HttpClientBuilder.create()
                .setDefaultCookieStore(cookieStore)
                .disableRedirectHandling()
                .build()) {
            // Follow the same-device callback back into the parent OIDC authorization flow.
            HttpResponse callbackResponse = client.execute(new HttpGet(responseToWallet.getRedirectUri()));
            String loginActionUrl = captureNextRedirect(callbackResponse);
            assertTrue(loginActionUrl.contains(OID4VPLoginActionsService.OID4VP_AUTH_LOGIN_PATH));
            String authCode = extractAuthCodeInRedirect(client.execute(new HttpGet(loginActionUrl)));
            assertNotNull(authCode, "Nested presentation should issue a fresh OIDC authorization code");
            assertFalse(authCode.isBlank());
            return authCode;
        }
    }

    private void assertCredentialIssued(String authorizationCode) throws Exception {
        // Exchange the parent code and verify that the credential endpoint returns the gated VC.
        String accessToken = requestAccessToken(authorizationCode, true);
        JsonNode tokenPayload = decodeJwtPayload(accessToken);
        String credentialIdentifier = tokenPayload
                .path(OAuth2Constants.AUTHORIZATION_DETAILS)
                .path(0)
                .path("credential_identifiers")
                .path(0)
                .asText(null);
        assertNotNull(credentialIdentifier, "The access token must advertise a credential identifier");
        HttpResponse response = requestCredentialWithIdentifier(accessToken, credentialIdentifier);
        String body = EntityUtils.toString(response.getEntity());
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode(), body);
        JsonNode credentialResponse = JsonSerialization.mapper.readTree(body);
        assertTrue(credentialResponse.has("credentials"), "A gated credential must be returned: " + body);
    }

    private JsonNode decodeJwtPayload(String jwt) throws Exception {
        String encodedPayload = jwt.split("\\.")[1];
        return JsonSerialization.mapper.readTree(
                new String(Base64.getUrlDecoder().decode(encodedPayload), StandardCharsets.UTF_8));
    }

    private void assertErrorResponse(
            HttpResponse response, int expectedStatus, String expectedError, String expectedDescription)
            throws Exception {
        assertEquals(expectedStatus, response.getStatusLine().getStatusCode());
        OAuth2ErrorRepresentation error = parseErrorResponse(response);
        assertEquals(expectedError, error.getError());
        assertTrue(error.getErrorDescription().contains(expectedDescription));
    }

    @SuppressWarnings("SameParameterValue")
    private void assertLogContains(String expectedMessage) {
        String newLogs = keycloak.getLogs().substring(logsAtTestStart.length());

        assertTrue(newLogs.contains(expectedMessage), "Expected log message after test start: " + expectedMessage);
    }
}
