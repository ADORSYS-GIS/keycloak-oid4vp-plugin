package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;
import org.keycloak.services.resources.admin.fgap.RealmPermissionEvaluator;

class EudiHubAdminResourceTest {

    private final RealmModel realm = mock(RealmModel.class);
    private final EudiHubService service = mock(EudiHubService.class);
    private final EudiHubAdminResource resource = new EudiHubAdminResource(realm, auth(), service);

    @Test
    void failsWhenTheOid4vpAuthFlowIsMissing() throws Exception {
        when(service.requestAccessCertificate(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new EudiHubService.AccessCertificateResult("certificate", null));

        Response response = request();

        assertEquals(409, response.getStatus());
        verify(realm, never()).addAuthenticatorConfig(any());
        verify(realm, never()).updateAuthenticatorConfig(any());
    }

    @Test
    void failsWhenTheOpenId4vpAuthenticatorIsMissing() throws Exception {
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow");
        when(realm.getFlowByAlias("oid4vp auth")).thenReturn(flow);
        when(realm.getAuthenticationExecutionsStream("flow")).thenReturn(Stream.empty());
        when(service.requestAccessCertificate(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new EudiHubService.AccessCertificateResult("certificate", null));

        Response response = request();

        assertEquals(409, response.getStatus());
        verify(realm, never()).addAuthenticatorConfig(any());
    }

    @Test
    void failsWhenTheAuthenticatorHasNoConfiguration() throws Exception {
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow");
        when(realm.getFlowByAlias("oid4vp auth")).thenReturn(flow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator("oid4vp-authenticator");
        when(realm.getAuthenticationExecutionsStream("flow")).thenReturn(Stream.of(execution));
        when(service.requestAccessCertificate(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new EudiHubService.AccessCertificateResult("certificate", null));

        Response response = request();

        assertEquals(409, response.getStatus());
        verify(realm, never()).addAuthenticatorConfig(any());
        verify(realm, never()).updateAuthenticatorConfig(any());
    }

    @Test
    void overridesOnlyTheAccessCertificate() throws Exception {
        AuthenticationFlowModel flow = new AuthenticationFlowModel();
        flow.setId("flow");
        when(realm.getFlowByAlias("oid4vp auth")).thenReturn(flow);

        AuthenticationExecutionModel execution = new AuthenticationExecutionModel();
        execution.setAuthenticator("oid4vp-authenticator");
        execution.setAuthenticatorConfig("config");
        when(realm.getAuthenticationExecutionsStream("flow")).thenReturn(Stream.of(execution));

        AuthenticatorConfigModel config = new AuthenticatorConfigModel();
        config.setId("config");
        Map<String, String> values = new LinkedHashMap<>();
        values.put("accessCertificate", "old");
        values.put("credentialTypes", "IdentityCredential");
        config.setConfig(values);
        when(realm.getAuthenticatorConfigById("config")).thenReturn(config);
        when(service.requestAccessCertificate(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(new EudiHubService.AccessCertificateResult("new", "Access Certificate TEST"));

        Response response = request();

        assertEquals(200, response.getStatus());
        assertEquals(Map.of("accessCertificate", "new", "name", "Access Certificate TEST"), response.getEntity());
        assertEquals("new", config.getConfig().get("accessCertificate"));
        assertEquals("IdentityCredential", config.getConfig().get("credentialTypes"));
        verify(realm).updateAuthenticatorConfig(config);
    }

    private Response request() {
        return resource.accessCertificate(new EudiHubAdminResource.AccessCertificateRequest(
                "portal-token", "11111111-1111-1111-1111-111111111111", "sandbox", "Access Certificate"));
    }

    private static AdminPermissionEvaluator auth() {
        AdminPermissionEvaluator auth = mock(AdminPermissionEvaluator.class);
        when(auth.realm()).thenReturn(mock(RealmPermissionEvaluator.class));
        return auth;
    }
}
