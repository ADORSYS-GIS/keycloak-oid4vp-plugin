package demo.lib;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.keycloak.OAuth2Constants;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.util.JsonSerialization;

// Encapsulates the HTTP calls the demo makes to Keycloak's OID4VP and OIDC endpoints.
public final class Oid4vpClient {

    private final HttpClient http;
    private final DemoConfig cfg;

    public Oid4vpClient(HttpClient http, DemoConfig cfg) {
        this.http = http;
        this.cfg = cfg;
    }

    public AuthorizationContext startAuthentication() throws Exception {
        String requestUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/oid4vp-auth/request?client_id="
                + urlEncode(cfg.clientId());
        return getJson(requestUrl, AuthorizationContext.class);
    }

    public RequestObject resolveRequestObject(AuthorizationContext authContext) throws Exception {
        return resolveRequestObject(authContext.getAuthorizationRequest());
    }

    public RequestObject resolveRequestObject(String authorizationRequest) throws Exception {
        String requestUri = extractQueryParam(authorizationRequest, "request_uri");
        String signedRequestJwt = getText(requestUri);
        return new JWSInput(signedRequestJwt).readJsonContent(RequestObject.class);
    }

    public AuthorizationContext fetchStatus(String transactionId) throws Exception {
        String statusUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/oid4vp-auth/status/" + transactionId;
        return getJson(statusUrl, AuthorizationContext.class);
    }

    public AuthorizationContext pollUntilTerminal(String transactionId, int attempts, Duration sleep)
            throws Exception {
        for (int i = 1; i <= attempts; i++) {
            AuthorizationContext status = fetchStatus(transactionId);
            if (status.getStatus() == AuthorizationContextStatus.SUCCESS
                    || status.getStatus() == AuthorizationContextStatus.ERROR) {
                return status;
            }
            Thread.sleep(sleep.toMillis());
        }
        throw new IllegalStateException("Timed out waiting for authentication status");
    }

    public void submitPresentation(RequestObject requestObject, String vpToken) throws Exception {
        postForm(
                requestObject.getResponseUri(),
                Oid4vpResponseFactory.createResponseForm(requestObject, vpToken));
    }

    public JsonNode exchangeAuthorizationCode(String authorizationCode) throws Exception {
        String tokenUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/protocol/openid-connect/token";
        Map<String, String> tokenForm = new LinkedHashMap<>();
        tokenForm.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE);
        tokenForm.put(OAuth2Constants.CLIENT_ID, cfg.clientId());
        tokenForm.put(OAuth2Constants.CLIENT_SECRET, cfg.clientSecret());
        tokenForm.put(OAuth2Constants.CODE, authorizationCode);

        return postFormJson(tokenUrl, tokenForm);
    }

    public AccessToken readAccessToken(String accessTokenStr) throws Exception {
        return new JWSInput(accessTokenStr).readJsonContent(AccessToken.class);
    }

    private <T> T getJson(String url, Class<T> clazz) throws Exception {
        return JsonSerialization.readValue(getText(url), clazz);
    }

    private String getText(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess("GET", url, response);
        return response.body();
    }

    private JsonNode postFormJson(String url, Map<String, String> form) throws Exception {
        HttpRequest request = buildFormPost(url, form);
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess("POST", url, response);
        return JsonSerialization.readValue(response.body(), JsonNode.class);
    }

    private void postForm(String url, Map<String, String> form) throws Exception {
        HttpRequest request = buildFormPost(url, form);
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        ensureSuccess("POST", url, response);
    }

    private HttpRequest buildFormPost(String url, Map<String, String> form) {
        return HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build();
    }

    private static String formEncode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            if (sb.length() > 0) {
                sb.append("&");
            }
            sb.append(urlEncode(entry.getKey()));
            sb.append("=");
            sb.append(urlEncode(entry.getValue()));
        }
        return sb.toString();
    }

    private static String extractQueryParam(String url, String name) {
        String query = URI.create(url).getRawQuery();
        if (query == null || query.isBlank()) {
            throw new IllegalArgumentException("No query string in URL: " + url);
        }

        for (String pair : query.split("&")) {
            int idx = pair.indexOf('=');
            if (idx <= 0) {
                continue;
            }
            String key = decode(pair.substring(0, idx));
            String value = decode(pair.substring(idx + 1));
            if (name.equals(key)) {
                return value;
            }
        }

        throw new IllegalArgumentException("Missing query param '" + name + "' in URL: " + url);
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private static String decode(String value) {
        return java.net.URLDecoder.decode(value, StandardCharsets.UTF_8);
    }

    private static void ensureSuccess(String method, String url, HttpResponse<String> response) {
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException(
                    method + " " + url + " failed: " + response.statusCode() + " -> " + response.body());
        }
    }
}
