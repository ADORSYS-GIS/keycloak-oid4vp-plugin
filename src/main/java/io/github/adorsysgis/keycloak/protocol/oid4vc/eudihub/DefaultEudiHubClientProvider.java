package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import static org.apache.http.HttpStatus.SC_BAD_GATEWAY;
import static org.apache.http.HttpStatus.SC_MULTIPLE_CHOICES;
import static org.apache.http.HttpStatus.SC_OK;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.jboss.logging.Logger;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.http.simple.SimpleHttp;
import org.keycloak.http.simple.SimpleHttpResponse;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

/** Uses Keycloak's HTTP clients to call the EUDI Hub Organization API. */
final class DefaultEudiHubClientProvider implements EudiHubClientProvider {

    private static final Logger logger = Logger.getLogger(DefaultEudiHubClientProvider.class);

    private final KeycloakSession session;

    DefaultEudiHubClientProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public <T> T get(String token, URI uri, Class<T> responseType) {
        return executeJsonRequest(
                () -> SimpleHttp.create(session)
                        .doGet(uri.toString())
                        .header(HttpHeaders.ACCEPT, "application/json")
                        .auth(token)
                        .asResponse(),
                responseType);
    }

    @Override
    public <T> T post(String token, URI uri, Object body, Class<T> responseType) {
        return executeJsonRequest(
                () -> SimpleHttp.create(session)
                        .doPost(uri.toString())
                        .header(HttpHeaders.ACCEPT, "application/json")
                        .auth(token)
                        .json(body)
                        .asResponse(),
                responseType);
    }

    @Override
    public byte[] download(String token, URI uri) {
        CloseableHttpClient client =
                session.getProvider(HttpClientProvider.class).getHttpClient();
        HttpGet request = new HttpGet(uri);
        request.setHeader(HttpHeaders.ACCEPT, "application/pkix-cert, application/octet-stream");
        request.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        try (CloseableHttpResponse response = client.execute(request)) {
            int status = response.getStatusLine().getStatusCode();
            byte[] payload = EntityUtils.toByteArray(response.getEntity());
            if (status < SC_OK || status >= SC_MULTIPLE_CHOICES) {
                logger.debugf("The EUDI Hub responded with HTTP status %s while downloading a certificate.", status);
                throw EudiHubService.error(
                        status, EudiHubService.problemDetail(new String(payload, StandardCharsets.UTF_8)));
            }
            return payload;
        } catch (IOException e) {
            logger.error("The EUDI Hub could not be reached or answered with an invalid certificate.", e);
            throw EudiHubService.error(
                    SC_BAD_GATEWAY, "The EUDI Hub could not be reached or answered with an invalid certificate.");
        }
    }

    private <T> T executeJsonRequest(JsonRequest request, Class<T> responseType) {
        try (SimpleHttpResponse response = request.execute()) {
            return readJson(response, responseType);
        } catch (IOException e) {
            logger.error("The EUDI Hub could not be reached or answered with invalid JSON.", e);
            throw EudiHubService.error(
                    SC_BAD_GATEWAY, "The EUDI Hub could not be reached or answered with invalid JSON.");
        }
    }

    private static <T> T readJson(SimpleHttpResponse response, Class<T> responseType) throws IOException {
        int status = response.getStatus();
        String payload = response.asString();
        if (status < SC_OK || status >= SC_MULTIPLE_CHOICES) {
            logger.debugf("The EUDI Hub responded with HTTP status %s.", status);
            throw EudiHubService.error(status, EudiHubService.problemDetail(payload));
        }
        return JsonSerialization.mapper.readValue(payload, responseType);
    }

    @Override
    public void close() {}

    @FunctionalInterface
    private interface JsonRequest {
        SimpleHttpResponse execute() throws IOException;
    }
}
