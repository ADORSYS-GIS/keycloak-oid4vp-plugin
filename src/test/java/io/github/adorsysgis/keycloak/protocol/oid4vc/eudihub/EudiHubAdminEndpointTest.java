package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.Environment;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.Organization;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.OrganizationsResponse;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory;
import jakarta.ws.rs.NotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpStatus;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.util.JsonSerialization;

/** End-to-end coverage of the EUDI Hub admin endpoints with a real Keycloak container. */
class EudiHubAdminEndpointTest extends BaseKeycloakTest {

    private static final String AUTH_CONFIG_ID = "oid4vp-auth-config-id";
    private static final String OID4VP_AUTH_FLOW = "oid4vp auth";
    private static final String ACCESS_CERTIFICATE_CONFIG_KEY = "accessCertificate";

    @Test
    void listsOrganizationsThroughTheAdminEndpoint() throws Exception {
        HttpResult result = post("organizations", Map.of("token", "organizations-" + UUID.randomUUID()));

        assertEquals(HttpStatus.SC_OK, result.status());
        OrganizationsResponse actual = JsonSerialization.mapper.treeToValue(result.body(), OrganizationsResponse.class);
        OrganizationsResponse expected = new OrganizationsResponse(List.of(new Organization(
                "stub-organization",
                "Stub Org",
                List.of(Environment.SANDBOX, Environment.LIVE),
                List.of("https://support.example.test"))));

        assertEquals(expected, actual);
    }

    @Test
    void passesPortalTokenUnchangedThroughBothHubRequests() throws Exception {
        String token = StubEudiHubClientProvider.TOKEN_PASSTHROUGH_TOKEN;
        HttpResult result = post("organizations", Map.of("token", token));

        assertEquals(HttpStatus.SC_OK, result.status());
        OrganizationsResponse actual = JsonSerialization.mapper.treeToValue(result.body(), OrganizationsResponse.class);
        OrganizationsResponse expected = new OrganizationsResponse(List.of(new Organization(
                "stub-organization",
                token,
                List.of(Environment.SANDBOX, Environment.LIVE),
                List.of("https://support.example.test/token/" + token))));

        assertEquals(expected, actual);
    }

    @Test
    void rejectsOrganizationRequestsWithoutViewRealmPermission() throws Exception {
        UnprivilegedAdmin user = createUnprivilegedAdmin();
        try {
            HttpResult result = post("organizations", Map.of("token", "organizations-forbidden"), userToken(user));
            assertEquals(HttpStatus.SC_FORBIDDEN, result.status());
        } finally {
            deleteUnprivilegedAdmin(user);
        }
    }

    @Test
    void rejectsCertificateRequestsWithoutManageRealmPermission() throws Exception {
        Map<String, String> originalConfig = authenticatorConfigContents();
        UnprivilegedAdmin user = createUnprivilegedAdmin();
        try {
            HttpResult result = post(
                    "access-certificate",
                    certificateRequest("create-forbidden-" + UUID.randomUUID(), "Forbidden Request"),
                    userToken(user));

            assertEquals(HttpStatus.SC_FORBIDDEN, result.status());
            assertEquals(originalConfig, authenticatorConfig().getConfig());
        } finally {
            deleteUnprivilegedAdmin(user);
        }
    }

    @Test
    void createsCertificateAndStoresItInTheAuthenticatorConfiguration() throws Exception {
        AuthenticatorConfigRepresentation original = authenticatorConfig();
        try {
            HttpResult result = post(
                    "access-certificate",
                    Map.of(
                            "token", "create-" + UUID.randomUUID(),
                            "organizationId", "stub-organization",
                            "environment", "sandbox",
                            "supportUri", "https://support.example.test",
                            "name", "Integration Test Certificate"));

            assertEquals(HttpStatus.SC_OK, result.status());
            String certificate = result.body().path("accessCertificate").asText();
            assertTrue(!certificate.isBlank());
            AuthenticatorConfigRepresentation updated = authenticatorConfig();
            assertEquals(certificate, updated.getConfig().get(ACCESS_CERTIFICATE_CONFIG_KEY));
            assertEquals(
                    "https://credentials.example.com/identity_credential,https://example.com/vct-alt",
                    updated.getConfig().get("credentialTypes"));
            assertEquals(
                    "Integration Test Certificate", result.body().path("name").asText());
        } finally {
            updateAuthenticatorConfig(original);
        }
    }

    @Test
    void reusesTheCertificateReturnedByTheHubWhenTheSigningKeyAlreadyHasOne() throws Exception {
        AuthenticatorConfigRepresentation original = authenticatorConfig();
        try {
            HttpResult result = post(
                    "access-certificate",
                    Map.of(
                            "token", "duplicate-" + UUID.randomUUID(),
                            "organizationId", "stub-organization",
                            "environment", "sandbox",
                            "supportUri", "https://support.example.test",
                            "name", "Duplicate Request"));

            assertEquals(HttpStatus.SC_OK, result.status());
            String certificate = result.body().path("accessCertificate").asText();
            assertTrue(!certificate.isBlank());
            assertEquals(certificate, authenticatorConfig().getConfig().get(ACCESS_CERTIFICATE_CONFIG_KEY));
            assertEquals("Existing Stub Certificate", result.body().path("name").asText());
        } finally {
            updateAuthenticatorConfig(original);
        }
    }

    @Test
    void propagatesNonConflictHubFailuresWithoutAttemptingCertificateRecovery() throws Exception {
        Map<String, String> originalConfig = authenticatorConfigContents();
        HttpResult result = post(
                "access-certificate",
                Map.of(
                        "token", "upstream-failure-" + UUID.randomUUID(),
                        "organizationId", "stub-organization",
                        "environment", "sandbox",
                        "supportUri", "https://support.example.test",
                        "name", "Unavailable Hub"));

        assertEquals(HttpStatus.SC_SERVICE_UNAVAILABLE, result.status());
        assertEquals("server_error", result.body().path("error").asText());
        assertEquals(
                "Stub Hub unavailable", result.body().path("error_description").asText());
        assertEquals(originalConfig, authenticatorConfig().getConfig());
    }

    @Test
    void propagatesConflictWhenNoCertificateMatchesTheSigningKey() throws Exception {
        Map<String, String> originalConfig = authenticatorConfigContents();
        HttpResult result =
                post("access-certificate", certificateRequest("duplicate-no-match-" + UUID.randomUUID(), "No Match"));

        assertEquals(HttpStatus.SC_CONFLICT, result.status());
        assertEquals("server_error", result.body().path("error").asText());
        assertEquals(
                "The Hub already has a certificate for this key",
                result.body().path("error_description").asText());
        assertEquals(originalConfig, authenticatorConfig().getConfig());
    }

    @ParameterizedTest
    @CsvSource({"duplicate-revoked-, revoked", "duplicate-expired-, expired"})
    void conflictsWhenTheMatchingHubCertificateIsNotValid(String tokenPrefix, String status) throws Exception {
        Map<String, String> originalConfig = authenticatorConfigContents();
        HttpResult result = post(
                "access-certificate",
                certificateRequest(tokenPrefix + UUID.randomUUID(), "Invalid Existing Certificate"));

        assertEquals(HttpStatus.SC_CONFLICT, result.status());
        assertEquals("server_error", result.body().path("error").asText());
        assertTrue(result.body().path("error_description").asText().contains("status: " + status));
        assertEquals(originalConfig, authenticatorConfig().getConfig());
    }

    @Test
    void propagatesConflictWhenDuplicateRecoveryReturnsAMalformedCertificate() throws Exception {
        Map<String, String> originalConfig = authenticatorConfigContents();
        HttpResult result = post(
                "access-certificate",
                certificateRequest("duplicate-malformed-" + UUID.randomUUID(), "Malformed Existing Certificate"));

        assertEquals(HttpStatus.SC_CONFLICT, result.status());
        assertEquals("server_error", result.body().path("error").asText());
        assertEquals(
                "The Hub already has a certificate for this key",
                result.body().path("error_description").asText());
        assertEquals(originalConfig, authenticatorConfig().getConfig());
    }

    @Test
    void createsAuthenticatorConfigWhenTheFlowExecutionHasNone() throws Exception {
        String executionId = addConfiglessAuthenticatorExecution();
        try {
            AuthenticationExecutionInfoRepresentation execution =
                    realm().flows().getExecutions(OID4VP_AUTH_FLOW).stream()
                            .filter(candidate -> executionId.equals(candidate.getId()))
                            .findFirst()
                            .orElseThrow();
            assertNull(execution.getAuthenticationConfig());

            // Make the configless execution the first OpenID4VP authenticator selected by the endpoint.
            execution.setPriority(Integer.MIN_VALUE);
            realm().flows().updateExecutions(OID4VP_AUTH_FLOW, execution);

            HttpResult result = post(
                    "access-certificate",
                    certificateRequest("create-no-config-" + UUID.randomUUID(), "New Authenticator Config"));

            assertEquals(HttpStatus.SC_OK, result.status());
            String createdCertificate = result.body().path("accessCertificate").asText();
            AuthenticationExecutionRepresentation updatedExecution =
                    realm().flows().getExecution(executionId);
            assertNotNull(updatedExecution.getAuthenticatorConfig());
            AuthenticatorConfigRepresentation createdConfig =
                    realm().flows().getAuthenticatorConfig(updatedExecution.getAuthenticatorConfig());
            assertEquals(createdCertificate, createdConfig.getConfig().get(ACCESS_CERTIFICATE_CONFIG_KEY));
        } finally {
            removeExecutionAndAuthenticatorConfig(executionId);
        }
    }

    private HttpResult post(String operation, Object body) throws IOException {
        return post(operation, body, adminToken());
    }

    private HttpResult post(String operation, Object body, String accessToken) throws IOException {
        HttpPost request = new HttpPost(adminEndpoint(operation));
        request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        request.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
        request.setEntity(
                new StringEntity(JsonSerialization.mapper.writeValueAsString(body), ContentType.APPLICATION_JSON));

        try (var response = httpClient.execute(request)) {
            String payload = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            return new HttpResult(response.getStatusLine().getStatusCode(), JsonSerialization.mapper.readTree(payload));
        }
    }

    private String adminEndpoint(String operation) {
        return KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("admin/realms/{realm}/eudi-hub/{operation}")
                .build(TEST_REALM_NAME, operation)
                .toString();
    }

    private static String adminToken() {
        return keycloak.getKeycloakAdminClient().tokenManager().getAccessTokenString();
    }

    private RealmResource realm() {
        return keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
    }

    private AuthenticatorConfigRepresentation authenticatorConfig() {
        return realm().flows().getAuthenticatorConfig(AUTH_CONFIG_ID);
    }

    private Map<String, String> authenticatorConfigContents() {
        return new HashMap<>(authenticatorConfig().getConfig());
    }

    private UnprivilegedAdmin createUnprivilegedAdmin() {
        String username = "eudi-hub-unprivileged-" + UUID.randomUUID();
        String password = UUID.randomUUID().toString();
        UserRepresentation user = new UserRepresentation();
        user.setUsername(username);
        user.setEnabled(true);

        var users = keycloak.getKeycloakAdminClient().realm("master").users();
        String userId;
        try (var response = users.create(user)) {
            assertEquals(HttpStatus.SC_CREATED, response.getStatus());
            String path = response.getLocation().getPath();
            userId = path.substring(path.lastIndexOf('/') + 1);
        }

        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        users.get(userId).resetPassword(credential);
        return new UnprivilegedAdmin(userId, username, password);
    }

    private String userToken(UnprivilegedAdmin user) throws IOException {
        List<BasicNameValuePair> params = List.of(
                new BasicNameValuePair(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD),
                new BasicNameValuePair(OAuth2Constants.CLIENT_ID, "admin-cli"),
                new BasicNameValuePair(OAuth2Constants.USERNAME, user.username()),
                new BasicNameValuePair(OAuth2Constants.PASSWORD, user.password()));
        HttpPost request = new HttpPost(KeycloakUriBuilder.fromUri(keycloak.getAuthServerUrl())
                .path("realms/master/protocol/openid-connect/token")
                .build()
                .toString());
        request.setEntity(new UrlEncodedFormEntity(params));

        try (var response = httpClient.execute(request)) {
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
            JsonNode tokenResponse = JsonSerialization.mapper.readTree(
                    EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
            return tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText();
        }
    }

    private void deleteUnprivilegedAdmin(UnprivilegedAdmin user) {
        keycloak.getKeycloakAdminClient().realm("master").users().delete(user.id());
    }

    private String addConfiglessAuthenticatorExecution() {
        Set<String> existingExecutionIds = realm().flows().getExecutions(OID4VP_AUTH_FLOW).stream()
                .map(AuthenticationExecutionInfoRepresentation::getId)
                .collect(Collectors.toSet());
        realm().flows().addExecution(OID4VP_AUTH_FLOW, Map.of("provider", OID4VPAuthenticatorFactory.PROVIDER_ID));
        return realm().flows().getExecutions(OID4VP_AUTH_FLOW).stream()
                .map(AuthenticationExecutionInfoRepresentation::getId)
                .filter(id -> !existingExecutionIds.contains(id))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("The configless execution was not added to the flow"));
    }

    private void removeExecutionAndAuthenticatorConfig(String executionId) {
        String configId = realm().flows().getExecution(executionId).getAuthenticatorConfig();
        realm().flows().removeExecution(executionId);
        if (configId != null) {
            try {
                realm().flows().getAuthenticatorConfig(configId);
                realm().flows().removeAuthenticatorConfig(configId);
            } catch (NotFoundException ignored) {
                // Removing the execution may also remove its configuration.
            }
        }
    }

    private static Map<String, String> certificateRequest(String token, String name) {
        return Map.of(
                "token", token,
                "organizationId", "stub-organization",
                "environment", "sandbox",
                "supportUri", "https://support.example.test",
                "name", name);
    }

    private record UnprivilegedAdmin(String id, String username, String password) {}

    private void updateAuthenticatorConfig(AuthenticatorConfigRepresentation config) {
        realm().flows().updateAuthenticatorConfig(config.getId(), config);
    }

    private record HttpResult(int status, JsonNode body) {}
}
