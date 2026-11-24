package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

class EudiHubServiceTest {

    private HttpServer server;
    private CloseableHttpClient httpClient;
    private EudiHubService service;

    @BeforeEach
    void setUp() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/org-management/v1/me", exchange -> {
            if (!"Bearer portal-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                respond(exchange, 401, "{\"detail\":\"Unauthorized\"}");
                return;
            }
            respond(exchange, 200, """
                    {
                      "organizations": [
                        {"id": "11111111-1111-1111-1111-111111111111", "name": "First"},
                        {"id": "22222222-2222-2222-2222-222222222222", "name": "Second"},
                        {"id": "33333333-3333-3333-3333-333333333333", "name": "Third"}
                      ]
                    }
                    """);
        });
        server.createContext("/org-management/v1/organizations/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.endsWith("22222222-2222-2222-2222-222222222222")) {
                respond(exchange, 500, "{\"detail\":\"Organization unavailable\"}");
                return;
            }
            if (path.endsWith("33333333-3333-3333-3333-333333333333")) {
                respond(exchange, 200, """
                        {
                          "contactInformation": {"supportUris": ["https://example.com/live-support"]},
                          "environments": ["sandbox", "live"]
                        }
                        """);
                return;
            }
            respond(exchange, 200, """
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

        assertEquals(3, organizations.size());
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

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] payload = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }
}
