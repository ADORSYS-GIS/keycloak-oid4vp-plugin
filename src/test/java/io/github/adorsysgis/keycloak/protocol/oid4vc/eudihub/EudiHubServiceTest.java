package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

class EudiHubServiceTest {

    private HttpServer server;
    private CloseableHttpClient httpClient;
    private EudiHubService service;
    private KeyPair signingKeyPair;
    private X509Certificate issuedCertificate;
    private byte[] issuedCertificateDer;
    private JsonNode receivedAccessCertificateRequest;

    @BeforeEach
    void setUp() throws Exception {
        CryptoIntegration.init(EudiHubServiceTest.class.getClassLoader());

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        signingKeyPair = generator.generateKeyPair();
        issuedCertificate =
                CertificateUtils.generateV1SelfSignedCertificate(signingKeyPair, "Issued Access Certificate");
        issuedCertificateDer = issuedCertificate.getEncoded();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/org-management/v1/me", exchange -> {
            if (!"Bearer portal-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                respondJson(exchange, 401, "{\"detail\":\"Unauthorized\"}");
                return;
            }
            respondJson(exchange, 200, """
                    {
                      "organizations": [
                        {"id": "11111111-1111-1111-1111-111111111111", "name": "First"},
                        {"id": "22222222-2222-2222-2222-222222222222", "name": "Second"},
                        {"id": "33333333-3333-3333-3333-333333333333", "name": "Third"},
                        {"id": "44444444-4444-4444-4444-444444444444", "name": "Fourth"}
                      ]
                    }
                    """);
        });
        server.createContext("/org-management/v1/organizations/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.endsWith("/access-certificates") && "POST".equals(exchange.getRequestMethod())) {
                receivedAccessCertificateRequest = JsonSerialization.mapper.readTree(
                        exchange.getRequestBody().readAllBytes());
                respondJson(exchange, 201, """
                        {"id": "cert-1", "name": "Access Certificate TEST", "status": "valid", "environment": "sandbox"}
                        """);
                return;
            }
            if (path.endsWith("/access-certificates/cert-1/download")) {
                respondBytes(exchange, 200, issuedCertificateDer);
                return;
            }
            if (path.endsWith("22222222-2222-2222-2222-222222222222")) {
                respondJson(exchange, 500, "{\"detail\":\"Organization unavailable\"}");
                return;
            }
            if (path.endsWith("33333333-3333-3333-3333-333333333333")) {
                respondJson(exchange, 200, """
                        {
                          "contactInformation": {"supportUris": ["https://example.com/live-support"]},
                          "environments": ["sandbox", "live"]
                        }
                        """);
                return;
            }
            if (path.endsWith("44444444-4444-4444-4444-444444444444")) {
                respondJson(exchange, 200, "{\"contactInformation\": {\"supportUris\": []}}");
                return;
            }
            respondJson(exchange, 200, """
                    {"contactInformation": {"supportUris": ["https://example.com/support"]}}
                    """);
        });
        server.start();

        httpClient = HttpClients.createDefault();
        KeycloakSession session = mock(KeycloakSession.class);
        HttpClientProvider httpClientProvider = mock(HttpClientProvider.class);
        when(session.getProvider(HttpClientProvider.class)).thenReturn(httpClientProvider);
        when(httpClientProvider.getHttpClient()).thenReturn(httpClient);
        when(httpClientProvider.getMaxConsumedResponseSize())
                .thenReturn(HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE);

        RealmModel realm = mock(RealmModel.class);
        KeycloakContext context = mock(KeycloakContext.class);
        when(session.getContext()).thenReturn(context);
        when(context.getRealm()).thenReturn(realm);

        KeyWrapper signingKey = new KeyWrapper();
        signingKey.setPrivateKey(signingKeyPair.getPrivate());
        signingKey.setPublicKey(signingKeyPair.getPublic());
        signingKey.setAlgorithm("ES256");
        signingKey.setUse(KeyUse.SIG);
        signingKey.setStatus(KeyStatus.ACTIVE);
        KeyManager keyManager = mock(KeyManager.class);
        when(session.keys()).thenReturn(keyManager);
        when(keyManager.getKeysStream(realm)).thenAnswer(invocation -> Stream.of(signingKey));

        service = new EudiHubService(
                session, "http://127.0.0.1:" + server.getAddress().getPort() + "/org-management", false);
    }

    @AfterEach
    void tearDown() throws IOException {
        server.stop(0);
        httpClient.close();
    }

    @Test
    void stripsBearerPrefix() {
        assertEquals("abc.def.ghi", EudiHubService.normalizeToken("  Bearer abc.def.ghi  "));
        assertEquals("abc.def.ghi", EudiHubService.normalizeToken("abc.def.ghi"));
        assertThrows(IllegalArgumentException.class, () -> EudiHubService.normalizeToken("   "));
        assertThrows(IllegalArgumentException.class, () -> EudiHubService.normalizeToken(null));
    }

    @Test
    void loadsOrganizationsWithSupportUris() throws Exception {
        List<EudiHubService.Organization> organizations = service.listOrganizations("Bearer portal-token");

        assertEquals(4, organizations.size());
        EudiHubService.Organization first = organizations.get(0);
        assertEquals("11111111-1111-1111-1111-111111111111", first.id());
        assertEquals("First", first.name());
        assertEquals(EudiHubService.Environment.SANDBOX, first.environment());
        assertEquals(List.of("https://example.com/support"), first.supportUris());

        // A broken organization detail must not hide the organization itself.
        EudiHubService.Organization second = organizations.get(1);
        assertEquals("Second", second.name());
        assertEquals(EudiHubService.Environment.SANDBOX, second.environment());
        assertTrue(second.supportUris().isEmpty());

        // The environment comes from the organization details, not from a form field.
        EudiHubService.Organization third = organizations.get(2);
        assertEquals("Third", third.name());
        assertEquals(EudiHubService.Environment.LIVE, third.environment());
        assertEquals(List.of("https://example.com/live-support"), third.supportUris());

        EudiHubService.Organization fourth = organizations.get(3);
        assertTrue(fourth.supportUris().isEmpty());
    }

    @Test
    void serializesEnvironmentForTheAdminApi() throws Exception {
        String live = JsonSerialization.mapper.writeValueAsString(
                new EudiHubService.Organization("id", "name", EudiHubService.Environment.LIVE, List.of()));
        assertTrue(live.contains("\"environment\":\"live\""), live);

        String sandbox = JsonSerialization.mapper.writeValueAsString(
                new EudiHubService.Organization("id", "name", EudiHubService.Environment.SANDBOX, List.of()));
        assertTrue(sandbox.contains("\"environment\":\"sandbox\""), sandbox);
    }

    @Test
    void requestsAccessCertificateForTheOpenId4vpSigningKey() throws Exception {
        String certificate = service.requestAccessCertificate(
                "portal-token", "11111111-1111-1111-1111-111111111111", "sandbox", "Access Certificate TEST");

        byte[] der = Base64.getDecoder().decode(certificate);
        X509Certificate parsed = (X509Certificate)
                CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        assertEquals(issuedCertificate, parsed);

        assertEquals(
                "Access Certificate TEST",
                receivedAccessCertificateRequest.get("name").asText());
        assertEquals(
                "sandbox", receivedAccessCertificateRequest.get("environment").asText());
        assertEquals(
                "https://example.com/support",
                receivedAccessCertificateRequest.get("supportUri").asText());

        String csr = receivedAccessCertificateRequest.get("csr").asText();
        assertTrue(csr.startsWith("-----BEGIN CERTIFICATE REQUEST-----"), csr);
        assertCsrMatches(csr, signingKeyPair.getPublic());
    }

    @Test
    void rejectsOrganizationWithoutSupportUri() {
        EudiHubService.EudiHubException failure = assertThrows(
                EudiHubService.EudiHubException.class,
                () -> service.requestAccessCertificate(
                        "portal-token", "44444444-4444-4444-4444-444444444444", "sandbox", "Access Certificate"));

        assertEquals(400, failure.getStatus());
        assertTrue(failure.getMessage().contains("support URI"), failure.getMessage());
    }

    @Test
    void normalizesEnvironment() {
        assertEquals("sandbox", EudiHubService.normalizeEnvironment(" Sandbox "));
        assertEquals("live", EudiHubService.normalizeEnvironment("LIVE"));
        assertThrows(IllegalArgumentException.class, () -> EudiHubService.normalizeEnvironment("production"));
        assertThrows(IllegalArgumentException.class, () -> EudiHubService.normalizeEnvironment(null));
    }

    @Test
    void rejectsUnauthorizedToken() {
        EudiHubService.EudiHubException failure =
                assertThrows(EudiHubService.EudiHubException.class, () -> service.listOrganizations("wrong-token"));

        assertEquals(401, failure.getStatus());
        assertEquals("Unauthorized", failure.getMessage());
    }

    @Test
    void requiresHttpsForProductionUrl() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new EudiHubService(mock(KeycloakSession.class), "http://example.com/org-management"));
    }

    private static void assertCsrMatches(String pem, PublicKey publicKey) throws Exception {
        String base64 = pem.replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                .replace("-----END CERTIFICATE REQUEST-----", "")
                .replaceAll("\\s", "");
        PKCS10CertificationRequest request =
                new PKCS10CertificationRequest(Base64.getDecoder().decode(base64));

        assertEquals(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()), request.getSubjectPublicKeyInfo());
        assertTrue(request.isSignatureValid(new JcaContentVerifierProviderBuilder().build(publicKey)));
    }

    private static void respondJson(HttpExchange exchange, int status, String body) throws IOException {
        respondBytes(exchange, status, body.getBytes(StandardCharsets.UTF_8));
    }

    private static void respondBytes(HttpExchange exchange, int status, byte[] payload) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }
}
