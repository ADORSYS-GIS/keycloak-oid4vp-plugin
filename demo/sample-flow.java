import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.Descriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.InputDescriptor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationDefinition;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.PresentationSubmission;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.ECPublicJWK;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.JWKSUtils;

class SampleFlow {
    private static final int ISSUER_SIGNED_JWT_LIFESPAN_SECS = 300;
    private static final int KB_JWT_LIFESPAN_SECS = 60;

    public static void main(String[] args) throws Exception {
        CryptoIntegration.init(SampleFlow.class.getClassLoader());
        DemoConfig cfg = DemoConfig.fromEnv();

        log("Starting OID4VP demo flow");
        log("Base URL: " + cfg.baseUrl);
        log("Realm: " + cfg.realm);
        log("OIDC Client ID: " + cfg.clientId);
        log("Username: " + cfg.username);

        HttpClient http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        // 1) Request an OpenID4VP authorization request
        String requestUrl = cfg.baseUrl + "/realms/" + cfg.realm + "/oid4vp-auth/request?client_id="
                + urlEncode(cfg.clientId);
        AuthorizationContext authContext = getJson(http, requestUrl, AuthorizationContext.class);
        requireNonBlank(authContext.getAuthorizationRequest(), "authorization_request");
        requireNonBlank(authContext.getTransactionId(), "transaction_id");
        log("Received authorization_request and transaction_id");

        // 2) Resolve the signed request object
        String requestUri = extractQueryParam(authContext.getAuthorizationRequest(), "request_uri");
        String signedRequestJwt = getText(http, requestUri);
        RequestObject requestObject = new JWSInput(signedRequestJwt).readJsonContent(RequestObject.class);
        log("Resolved request object");
        log("nonce: " + requestObject.getNonce());
        log("verifier client_id: " + requestObject.getClientId());

        // 3) Build an SD-JWT credential and a VP token (wallet replacement)
        JWK issuerJwk = loadJwk(Path.of(cfg.issuerJwkPath));
        JWK holderPrivateJwk = loadJwk(Path.of(cfg.holderJwkPath));
        JWK holderPublicJwk = loadJwk(Path.of(cfg.holderJwkPath));

        String sdJwt = buildSdJwtCredential(cfg, issuerJwk, holderPublicJwk);
        String vpToken = presentSdJwt(sdJwt, requestObject.getNonce(), requestObject.getClientId(), holderPrivateJwk);
        log("Prepared SD-JWT VP token");

        // 4) Build an OpenID4VP response
        Map<String, String> responseForm = new LinkedHashMap<>();
        if (requestObject.getPresentationDefinition() != null) {
            PresentationSubmission submission = buildPresentationSubmission(requestObject.getPresentationDefinition());
            responseForm.put(ResponseObject.VP_TOKEN_KEY, vpToken);
            responseForm.put(
                    ResponseObject.PRESENTATION_SUBMISSION_KEY,
                    JsonSerialization.writeValueAsString(submission));
        } else if (requestObject.getDcqlQuery() != null) {
            DcqlQuery query = requestObject.getDcqlQuery();
            Credential credential = query.getCredentials().getFirst();
            Map<String, List<String>> vpTokenMap = Map.of(credential.getId(), List.of(vpToken));
            responseForm.put(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap));
        } else {
            throw new IllegalStateException("Request object contains neither presentation_definition nor dcql_query");
        }
        responseForm.put(ResponseObject.STATE_KEY, requestObject.getState());

        String responseUrl = cfg.baseUrl + "/realms/" + cfg.realm + "/oid4vp-auth/response";
        postForm(http, responseUrl, responseForm);
        log("Submitted OpenID4VP response");

        // 5) Poll for status
        String statusUrl = cfg.baseUrl + "/realms/" + cfg.realm + "/oid4vp-auth/status/" + authContext.getTransactionId();
        AuthorizationContext status = pollStatus(http, statusUrl, 30, Duration.ofSeconds(1));
        if (status.getStatus() != AuthorizationContextStatus.SUCCESS) {
            throw new IllegalStateException("Authentication failed: " + status.getErrorDescription());
        }
        requireNonBlank(status.getAuthorizationCode(), "authorization_code");
        log("Authentication succeeded. Received authorization_code");

        // 6) Exchange the auth code for an access token
        String tokenUrl = cfg.baseUrl + "/realms/" + cfg.realm + "/protocol/openid-connect/token";
        Map<String, String> tokenForm = new LinkedHashMap<>();
        tokenForm.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE);
        tokenForm.put(OAuth2Constants.CLIENT_ID, cfg.clientId);
        tokenForm.put(OAuth2Constants.CLIENT_SECRET, cfg.clientSecret);
        tokenForm.put(OAuth2Constants.CODE, status.getAuthorizationCode());
        if (cfg.redirectUri != null && !cfg.redirectUri.isBlank()) {
            tokenForm.put(OAuth2Constants.REDIRECT_URI, cfg.redirectUri);
        }

        JsonNode tokenResponse = postFormJson(http, tokenUrl, tokenForm);
        String accessTokenStr = tokenResponse.path(OAuth2Constants.ACCESS_TOKEN).asText(null);
        requireNonBlank(accessTokenStr, "access_token");

        AccessToken accessToken = new JWSInput(accessTokenStr).readJsonContent(AccessToken.class);
        log("Access token issued for user: " + accessToken.getPreferredUsername());
        log("Issuer: " + accessToken.getIssuer());
        log("OID4VP demo flow complete.");
    }

    private static AuthorizationContext pollStatus(
            HttpClient http, String url, int attempts, Duration sleep) throws Exception {
        for (int i = 1; i <= attempts; i++) {
            AuthorizationContext status = getJson(http, url, AuthorizationContext.class);
            if (status.getStatus() == AuthorizationContextStatus.SUCCESS
                    || status.getStatus() == AuthorizationContextStatus.ERROR) {
                return status;
            }
            Thread.sleep(sleep.toMillis());
        }
        throw new IllegalStateException("Timed out waiting for authentication status");
    }

    private static PresentationSubmission buildPresentationSubmission(PresentationDefinition definition) {
        InputDescriptor inputDescriptor = definition.getInputDescriptors().getFirst();

        PresentationSubmission submission = new PresentationSubmission();
        submission.setId(UUID.randomUUID().toString());
        submission.setDefinitionId(definition.getId());

        Descriptor descriptor = new Descriptor();
        descriptor.setId(inputDescriptor.getId());
        descriptor.setFormat(Descriptor.Format.VC_SD_JWT);
        descriptor.setPath("$");
        submission.setDescriptorMap(List.of(descriptor));

        return submission;
    }

    private static String buildSdJwtCredential(DemoConfig cfg, JWK issuerJwk, JWK holderPublicJwk) throws Exception {
        KeyWrapper issuerKeyWrapper = getRsaKeyWrapper(issuerJwk);
        SignatureSignerContext issuerSigner = new AsymmetricSignatureSignerContext(issuerKeyWrapper);

        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(OAuth2Constants.ISSUER, cfg.issuer);
        claimSet.put("vct", cfg.vct);
        claimSet.put(OAuth2Constants.USERNAME, cfg.username);
        claimSet.put("iat", Time.currentTime());
        claimSet.put("exp", Time.currentTime() + ISSUER_SIGNED_JWT_LIFESPAN_SECS);

        // Bind to holder key
        JWK publicOnly = stripEcPrivateKey(holderPublicJwk);
        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set("jwk", JsonSerialization.mapper.valueToTree(publicOnly));
        claimSet.set("cnf", cnf);

        DisclosureSpec.Builder disclosure = DisclosureSpec.builder()
                .withUndisclosedClaim(OAuth2Constants.USERNAME, "eI8ZWm9QnKPpNPeNenHdhQ")
                .withDecoyClaim("G02NSrQfjFXQ7Io09syajA");

        IssuerSignedJWT issuerSignedJWT = IssuerSignedJWT.builder()
                .withClaims(claimSet, disclosure.build())
                .build();

        return SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(issuerSigner)
                .build()
                .toSdJwtString();
    }

    private static String presentSdJwt(String sdJwt, String nonce, String aud, JWK holderKey) throws Exception {
        JsonWebToken kbJwtClaims = new JsonWebToken();
        long now = Time.currentTime();
        kbJwtClaims.iat(now);
        kbJwtClaims.exp(now + KB_JWT_LIFESPAN_SECS);
        kbJwtClaims.getOtherClaims().put("nonce", nonce);
        kbJwtClaims.getOtherClaims().put("aud", aud);

        KeyWrapper holderKeyWrapper = getEcKeyWrapper(holderKey);
        SignatureSignerContext signer = new ECDSASignatureSignerContext(holderKeyWrapper);

        SdJwtVP sdJwtVP = SdJwtVP.of(sdJwt);
        return sdJwtVP.present(null, true, JsonSerialization.mapper.valueToTree(kbJwtClaims), signer);
    }

    private static <T> T getJson(HttpClient http, String url, Class<T> clazz) throws Exception {
        String body = getText(http, url);
        return JsonSerialization.readValue(body, clazz);
    }

    private static String getText(HttpClient http, String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("GET " + url + " failed: " + response.statusCode() + " -> " + response.body());
        }
        return response.body();
    }

    private static void postForm(HttpClient http, String url, Map<String, String> form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("POST " + url + " failed: " + response.statusCode() + " -> " + response.body());
        }
    }

    private static JsonNode postFormJson(HttpClient http, String url, Map<String, String> form) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formEncode(form)))
                .build();

        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() / 100 != 2) {
            throw new IllegalStateException("POST " + url + " failed: " + response.statusCode() + " -> " + response.body());
        }
        return JsonSerialization.readValue(response.body(), JsonNode.class);
    }

    private static String formEncode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            if (sb.length() > 0) sb.append("&");
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
            if (idx <= 0) continue;
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

    private static void requireNonBlank(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing required field: " + field);
        }
    }

    private static JWK loadJwk(Path path) throws IOException {
        if (!Files.exists(path)) {
            throw new IllegalArgumentException("JWK file not found: " + path);
        }
        try (InputStream in = Files.newInputStream(path)) {
            return JsonSerialization.readValue(in, JWK.class);
        }
    }

    private static JWK stripEcPrivateKey(JWK jwk) {
        jwk.setOtherClaims("d", null);
        return jwk;
    }

    private static KeyWrapper getEcKeyWrapper(JWK jwk) throws Exception {
        if (!Objects.equals(jwk.getKeyType(), "EC")) {
            throw new IllegalArgumentException("Only EC keys are supported for holder key");
        }
        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        keyWrapper.setPrivateKey(ECTestUtils.getEcPrivateKey(jwk));
        return keyWrapper;
    }

    private static KeyWrapper getRsaKeyWrapper(JWK jwk) throws Exception {
        if (!Objects.equals(jwk.getKeyType(), "RSA")) {
            throw new IllegalArgumentException("Only RSA keys are supported for issuer key");
        }
        KeyWrapper keyWrapper = JWKSUtils.getKeyWrapper(jwk);
        keyWrapper.setPrivateKey(RSATestUtils.getRsaPrivateKey(jwk));
        return keyWrapper;
    }

    private static void log(String msg) {
        System.out.println("[demo] " + msg);
    }

    private record DemoConfig(
            String baseUrl,
            String realm,
            String clientId,
            String clientSecret,
            String redirectUri,
            String username,
            String vct,
            String issuer,
            String issuerJwkPath,
            String holderJwkPath) {

        static DemoConfig fromEnv() {
            String baseUrl = env("DEMO_BASE_URL", "http://localhost:8080");
            String realm = env("DEMO_REALM", "oid4vp-demo");
            String clientId = env("DEMO_CLIENT_ID", "test-app");
            String clientSecret = env("DEMO_CLIENT_SECRET", "password");
            String redirectUri = env("DEMO_REDIRECT_URI", "http://localhost:4200/callback");
            String username = env("DEMO_USERNAME", "test-user@localhost");
            String vct = env("DEMO_VCT", "https://credentials.example.com/identity_credential");
            String issuerJwk = env("DEMO_ISSUER_JWK", "demo/keys/keycloak.json");
            String holderJwk = env("DEMO_HOLDER_JWK", "demo/keys/user-wallet-key.json");
            String issuer = baseUrl + "/realms/" + realm;

            return new DemoConfig(
                    baseUrl,
                    realm,
                    clientId,
                    clientSecret,
                    redirectUri,
                    username,
                    vct,
                    issuer,
                    issuerJwk,
                    holderJwk);
        }

        private static String env(String key, String defaultValue) {
            String value = System.getenv(key);
            return (value == null || value.isBlank()) ? defaultValue : value;
        }
    }

    // Minimal RSA/EC helpers (adapted from src/test/utils)
    private static final class RSATestUtils {
        private static java.security.PrivateKey getRsaPrivateKey(JWK jwk) throws Exception {
            byte[] n = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("n"));
            byte[] e = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("e"));
            byte[] d = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("d"));
            byte[] p = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("p"));
            byte[] q = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("q"));
            byte[] dp = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("dp"));
            byte[] dq = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("dq"));
            byte[] qi = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("qi"));

            java.math.BigInteger bn = new java.math.BigInteger(1, n);
            java.math.BigInteger be = new java.math.BigInteger(1, e);
            java.math.BigInteger bd = new java.math.BigInteger(1, d);
            java.math.BigInteger bp = new java.math.BigInteger(1, p);
            java.math.BigInteger bq = new java.math.BigInteger(1, q);
            java.math.BigInteger bdp = new java.math.BigInteger(1, dp);
            java.math.BigInteger bdq = new java.math.BigInteger(1, dq);
            java.math.BigInteger bqi = new java.math.BigInteger(1, qi);

            java.security.spec.RSAPrivateCrtKeySpec spec =
                    new java.security.spec.RSAPrivateCrtKeySpec(bn, be, bd, bp, bq, bdp, bdq, bqi);
            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        }
    }

    private static final class ECTestUtils {
        private static java.security.PrivateKey getEcPrivateKey(JWK jwk) throws Exception {
            if (!Objects.equals(jwk.getKeyType(), "EC")) {
                throw new IllegalArgumentException("Only EC keys are supported");
            }

            String crv = (String) jwk.getOtherClaims().get(ECPublicJWK.CRV);
            java.security.spec.ECParameterSpec ecSpec = getECParameterSpec(crv);

            byte[] dBytes = Base64.getUrlDecoder().decode((String) jwk.getOtherClaims().get("d"));
            java.math.BigInteger dValue = new java.math.BigInteger(1, dBytes);

            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
            return keyFactory.generatePrivate(new java.security.spec.ECPrivateKeySpec(dValue, ecSpec));
        }

        private static java.security.spec.ECParameterSpec getECParameterSpec(String jwkCrv) throws Exception {
            String crvStdName = switch (jwkCrv) {
                case "P-256" -> "secp256r1";
                case "P-384" -> "secp384r1";
                case "P-521" -> "secp521r1";
                default -> throw new IllegalArgumentException("Unsupported curve: " + jwkCrv);
            };

            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("EC");
            params.init(new java.security.spec.ECGenParameterSpec(crvStdName));
            return params.getParameterSpec(java.security.spec.ECParameterSpec.class);
        }
    }
}
