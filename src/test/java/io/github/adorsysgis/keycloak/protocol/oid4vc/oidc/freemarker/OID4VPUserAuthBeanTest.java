package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_CLIENT_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_REALM_NAME;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.LOGIN_METHOD_OID4VP;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.PARAM_LOGIN_METHOD;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.CodeChallengeDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jboss.resteasy.specimpl.ResteasyUriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.OAuth2Constants;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test that view data are properly constructed in OID4VPUserAuthBean.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@ExtendWith(MockitoExtension.class)
public class OID4VPUserAuthBeanTest {

    @Mock
    KeycloakSession session;

    @Mock
    KeycloakContext context;

    @Mock
    RealmModel realm;

    @Mock
    OID4VPUserAuthEndpoint oid4vp;

    @BeforeEach
    void setUp() {
        // session.getContext()
        Mockito.lenient().when(session.getContext()).thenReturn(context);

        // realm.getName()
        Mockito.lenient().when(realm.getName()).thenReturn(TEST_REALM_NAME);

        // oid4vp.checkClient()
        Mockito.lenient()
                .doAnswer(invocation -> {
                    if (!TEST_CLIENT_ID.equals(invocation.getArgument(0))) {
                        throw new IllegalArgumentException();
                    }
                    return null;
                })
                .when(oid4vp)
                .checkClient(anyString());

        Mockito.lenient()
                .when(oid4vp.getAuthenticationProfilesForClient(TEST_CLIENT_ID))
                .thenReturn(List.of(new AuthenticationProfile()
                        .setId(AuthenticationProfile.DEFAULT_PROFILE_ID)
                        .setDisplayCta(Map.of("en", AuthenticationProfile.DEFAULT_CTA))));

        // oid4vp.startAuthentication()
        AuthorizationContext authContext = new AuthorizationContext();
        authContext.setAuthorizationRequest("openid4vp://authorize?client_id=<>&request_uri=<>");
        authContext.setTransactionId(UUID.randomUUID().toString());
        Mockito.lenient()
                .when(oid4vp.startAuthentication(
                        eq(TEST_CLIENT_ID),
                        nullable(String.class),
                        nullable(OIDCAuthSession.class),
                        nullable(CodeChallengeDetails.class)))
                .thenReturn(authContext);
    }

    @Test
    public void shouldSuccessfullyBuildBean() {
        OID4VPUserAuthBean bean = createTestBean();

        // Login URL should contain login_method=oid4vp
        URI loginUrl = URI.create(bean.getLoginProfiles().getFirst().getLoginUrl());
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(loginUrl);
        String loginMethod = uriInfo.getQueryParameters().getFirst(PARAM_LOGIN_METHOD);
        assertEquals(LOGIN_METHOD_OID4VP, loginMethod);

        // Login Action URL
        assertNotNull(bean.getLoginActionUrl());

        // Auth Context should be created
        var authContext = bean.getAuthContext();
        assertTrue(authContext.getAuthReqLink().startsWith("openid4vp://"));
        assertTrue(authContext.getAuthReqQrCode().startsWith("data:image/png;base64,"));
        assertNotNull(authContext.getAuthStatusUrl());
    }

    @Test
    public void shouldNotInjectLoginUrlIfInvalidClient() {
        OID4VPUserAuthBean bean = createTestBean("unknown-client", true);
        assertTrue(bean.getLoginProfiles().isEmpty()); // Empty because clientId is invalid
    }

    @Test
    public void shouldExposeOneLoginProfilePerConfiguredAuthProfile() {
        Mockito.when(oid4vp.getAuthenticationProfilesForClient(TEST_CLIENT_ID))
                .thenReturn(List.of(
                        new AuthenticationProfile()
                                .setId(AuthenticationProfile.DEFAULT_PROFILE_ID)
                                .setDisplayCta(Map.of("en", "Sign in with a wallet")),
                        new AuthenticationProfile().setId("dual").setDisplayCta(Map.of("en", "Dual login"))));

        OID4VPUserAuthBean bean = createTestBean();

        var loginProfiles = bean.getLoginProfiles();
        assertEquals(2, loginProfiles.size());
        assertEquals(
                AuthenticationProfile.DEFAULT_PROFILE_ID,
                loginProfiles.getFirst().getId());
        assertEquals("Sign in with a wallet", loginProfiles.getFirst().getDisplayName());
        assertEquals("dual", loginProfiles.get(1).getId());
        assertEquals("Dual login", loginProfiles.get(1).getDisplayName());

        ResteasyUriInfo defaultLoginUri =
                new ResteasyUriInfo(URI.create(loginProfiles.getFirst().getLoginUrl()));
        assertEquals(
                AuthenticationProfile.DEFAULT_PROFILE_ID,
                defaultLoginUri.getQueryParameters().getFirst(OID4VPUserAuthEndpoint.PROFILE_ID_PARAM));

        ResteasyUriInfo dualLoginUri =
                new ResteasyUriInfo(URI.create(loginProfiles.get(1).getLoginUrl()));
        assertEquals("dual", dualLoginUri.getQueryParameters().getFirst(OID4VPUserAuthEndpoint.PROFILE_ID_PARAM));
    }

    @Test
    public void shouldNotInjectAuthContextIfLoginMethodNotExplicit() {
        OID4VPUserAuthBean bean = createTestBean(TEST_CLIENT_ID, false);
        assertNull(bean.getAuthContext()); // Null because no login_method param
    }

    @Test
    public void shouldNotRecreateAuthContextInSameParsingSession() {
        OID4VPUserAuthBean bean = createTestBean();

        var authContext1 = bean.getAuthContext();
        assertNotNull(authContext1);

        var authContext2 = bean.getAuthContext();
        assertEquals(authContext1, authContext2);
    }

    private OID4VPUserAuthBean createTestBean() {
        return createTestBean(TEST_CLIENT_ID, true);
    }

    private OID4VPUserAuthBean createTestBean(String clientId, boolean withLoginMethod) {
        UriBuilder uriBuilder =
                UriBuilder.fromUri("https://keycloak.org/").queryParam(OAuth2Constants.CLIENT_ID, clientId);

        if (withLoginMethod) {
            uriBuilder.queryParam(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP);
        }

        URI uri = uriBuilder.build();
        mockContextUri(uri);

        String authSessionId = UUID.randomUUID().toString();
        return new OID4VPUserAuthBean(session, realm, oid4vp, uri, authSessionId);
    }

    private void mockContextUri(URI uri) {
        ResteasyUriInfo uriInfo = new ResteasyUriInfo(uri);
        KeycloakUriInfo mockUri = Mockito.mock(KeycloakUriInfo.class);

        Mockito.lenient().when(mockUri.getRequestUri()).thenReturn(uriInfo.getRequestUri());
        Mockito.lenient().when(mockUri.getBaseUri()).thenReturn(uriInfo.getBaseUri());
        Mockito.lenient().when(mockUri.getQueryParameters()).thenReturn(uriInfo.getQueryParameters());

        Mockito.lenient().when(session.getContext().getUri()).thenReturn(mockUri);
    }
}
