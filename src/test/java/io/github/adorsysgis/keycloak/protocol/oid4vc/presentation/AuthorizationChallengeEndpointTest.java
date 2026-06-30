package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseUserAuthEndpointTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;

/**
 * End-to-end test for the OID4VCI "presentation during issuance" authorization challenge flow.
 */
class AuthorizationChallengeEndpointTest extends OID4VPBaseUserAuthEndpointTest {

    @Test
    @DisplayName("should issue authorization_code after presentation during issuance")
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
        var realmUri = java.net.URI.create(getTestRealmEndpoint());
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

        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);

        // 2. Wallet submits an OpenID4VP Authorization Error Response (OID4VCI §6.2.1.1)
        var errorResponse = String.format(
                "{\"error\":\"%s\",\"error_description\":\"User declined\",\"state\":\"%s\"}",
                OAuthErrorException.ACCESS_DENIED, requestObject.getState());

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, errorResponse)));

        // 3. -> 400 error response, no authorization_code (not an empty 200)
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

        var requestObjectJwt = challenge.getOpenid4vpRequest().get("request").asText();
        RequestObject requestObject = new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);

        // 2. Present with a Key Binding JWT audience that is NOT the expected verifier (forwarding attempt)
        var tamperedResponse = buildOpenid4vpResponseJson(sdJwt, requestObject, "https://attacker.example.com");

        var resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.getAuthSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, tamperedResponse)));

        // 3. -> rejected, no authorization_code issued
        assertNotEquals(HttpStatus.SC_OK, resume.getStatusLine().getStatusCode());
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
