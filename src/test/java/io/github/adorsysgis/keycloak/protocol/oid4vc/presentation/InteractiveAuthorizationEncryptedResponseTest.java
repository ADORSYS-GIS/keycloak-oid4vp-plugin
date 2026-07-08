package io.github.adorsysgis.keycloak.protocol.oid4vc.presentation;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthenticatorFactory.VCT_CONFIG_DEFAULT;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseUserAuthEndpointTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import java.net.URI;
import java.util.List;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.protocol.oidc.utils.PkceUtils;

/**
 * End-to-end tests for the encrypted variant of the OID4VCI §6 interactive authorization flow. On a
 * realm whose verifier is configured for encrypted responses ({@code direct_post.jwt}), the
 * Authorization Challenge Endpoint must request the presentation with {@code response_mode=ia_post.jwt}
 * and accept an encrypted {@code openid4vp_response} (OID4VCI §6.2.1.1).
 */
class InteractiveAuthorizationEncryptedResponseTest extends OID4VPBaseUserAuthEndpointTest {

    private static final String TEST_USER_HAIP = "test-user-haip";

    @Override
    public String getActiveTestRealm() {
        return TEST_REALM_HAIP_NAME;
    }

    @Test
    @DisplayName(
            "the interactive challenge requests ia_post.jwt and advertises an encryption key when the verifier is encrypted")
    void interactiveChallengeUsesEncryptedResponseMode() throws Exception {
        RequestObject requestObject = initiateInteractiveChallenge();

        // The encrypted verifier configuration (direct_post.jwt) maps to the encrypted interactive mode.
        assertEquals(ResponseMode.IA_POST_JWT, requestObject.getResponseMode());

        // An ephemeral encryption key must be advertised so the wallet can encrypt its response.
        assertNotNull(requestObject.getClientMetadata().getJwks(), "an encryption key must be advertised");
        assertEquals(1, requestObject.getClientMetadata().getJwks().getKeys().length);

        // The request stays bound to the challenge endpoint origin (forwarding protection, §6.2.1.5).
        URI realmUri = URI.create(getTestRealmEndpoint());
        String challengeOrigin = realmUri.getScheme() + "://" + realmUri.getAuthority();
        assertEquals(List.of(challengeOrigin), requestObject.getExpectedOrigins());
    }

    @Test
    @DisplayName("an encrypted openid4vp_response (ia_post.jwt) is accepted and yields an authorization_code")
    void encryptedInteractiveResponseIssuesAuthorizationCode() throws Exception {
        String sdJwt = sdJwtVPTestUtils.requestSdJwtCredential(VCT_CONFIG_DEFAULT, TEST_USER_HAIP);

        Challenge challenge = initiateInteractiveChallengeVerbose();
        RequestObject requestObject = new JWSInput(challenge.requestJwt()).readJsonContent(RequestObject.class);
        assertEquals(ResponseMode.IA_POST_JWT, requestObject.getResponseMode());

        String encryptedResponse = buildEncryptedOpenid4vpResponseJson(sdJwt, requestObject);

        HttpResponse resume = postChallenge(List.of(
                new BasicNameValuePair(AuthorizationChallengeEndpoint.AUTH_SESSION_PARAM, challenge.authSession()),
                new BasicNameValuePair(AuthorizationChallengeEndpoint.OPENID4VP_RESPONSE_PARAM, encryptedResponse)));

        assertEquals(HttpStatus.SC_OK, resume.getStatusLine().getStatusCode());
        assertNotNull(
                parseHttpResponse(resume, AuthorizationChallengeResponse.class).getAuthorizationCode());
    }

    private RequestObject initiateInteractiveChallenge() throws Exception {
        return new JWSInput(initiateInteractiveChallengeVerbose().requestJwt()).readJsonContent(RequestObject.class);
    }

    private Challenge initiateInteractiveChallengeVerbose() throws Exception {
        var codeVerifier = PkceUtils.generateCodeVerifier();
        var codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);

        HttpResponse initiate = postChallenge(List.of(
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID),
                new BasicNameValuePair(OAuth2Constants.SCOPE, OAuth2Constants.SCOPE_OPENID),
                new BasicNameValuePair(
                        AuthorizationChallengeEndpoint.INTERACTION_TYPES_SUPPORTED_PARAM,
                        AuthorizationChallengeEndpoint.INTERACTION_OPENID4VP_PRESENTATION),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE, codeChallenge),
                new BasicNameValuePair(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)));

        assertEquals(HttpStatus.SC_UNAUTHORIZED, initiate.getStatusLine().getStatusCode());
        AuthorizationChallengeResponse challenge = parseHttpResponse(initiate, AuthorizationChallengeResponse.class);
        assertEquals(AuthorizationChallengeEndpoint.ERROR_INSUFFICIENT_AUTHORIZATION, challenge.getError());
        assertNotNull(challenge.getAuthSession());
        return new Challenge(
                challenge.getAuthSession(),
                challenge.getOpenid4vpRequest().get("request").asText());
    }

    private HttpResponse postChallenge(List<BasicNameValuePair> form) throws Exception {
        String url = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path(AuthorizationChallengeEndpointFactory.PROVIDER_ID)
                .build()
                .toString();
        HttpPost post = new HttpPost(url);
        post.setEntity(new UrlEncodedFormEntity(form));
        return httpClient.execute(post);
    }

    private record Challenge(String authSession, String requestJwt) {}
}
