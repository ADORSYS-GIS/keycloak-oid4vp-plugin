package demo.lib;

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

public final class DemoSupport {

    public static final int ISSUER_SIGNED_JWT_LIFESPAN_SECS = 300;
    public static final int KB_JWT_LIFESPAN_SECS = 60;

    private DemoSupport() {}

    public static void bootstrapCrypto() {
        CryptoIntegration.init(DemoSupport.class.getClassLoader());
    }

    public static HttpClient newHttpClient() {
        return HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    public static AuthorizationContext requestAuthorizationContext(HttpClient http, DemoConfig cfg) throws Exception {
        String requestUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/oid4vp-auth/request?client_id="
                + urlEncode(cfg.clientId());
        return getJson(http, requestUrl, AuthorizationContext.class);
    }

    public static RequestObject resolveRequestObject(HttpClient http, AuthorizationContext authContext) throws Exception {
        return resolveRequestObject(http, authContext.getAuthorizationRequest());
    }

    public static RequestObject resolveRequestObject(HttpClient http, String authorizationRequest) throws Exception {
        String requestUri = extractQueryParam(authorizationRequest, "request_uri");
        String signedRequestJwt = getText(http, requestUri);
        return new JWSInput(signedRequestJwt).readJsonContent(RequestObject.class);
    }

    public static AuthorizationContext fetchStatus(HttpClient http, DemoConfig cfg, String transactionId)
            throws Exception {
        String statusUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/oid4vp-auth/status/" + transactionId;
        return getJson(http, statusUrl, AuthorizationContext.class);
    }

    public static AuthorizationContext pollUntilTerminal(
            HttpClient http, DemoConfig cfg, String transactionId, int attempts, Duration sleep) throws Exception {
        for (int i = 1; i <= attempts; i++) {
            AuthorizationContext status = fetchStatus(http, cfg, transactionId);
            if (status.getStatus() == AuthorizationContextStatus.SUCCESS
                    || status.getStatus() == AuthorizationContextStatus.ERROR) {
                return status;
            }
            Thread.sleep(sleep.toMillis());
        }
        throw new IllegalStateException("Timed out waiting for authentication status");
    }

    public static JsonNode exchangeAuthorizationCode(HttpClient http, DemoConfig cfg, String authorizationCode)
            throws Exception {
        String tokenUrl = cfg.baseUrl() + "/realms/" + cfg.realm() + "/protocol/openid-connect/token";
        Map<String, String> tokenForm = new LinkedHashMap<>();
        tokenForm.put(OAuth2Constants.GRANT_TYPE, OAuth2Constants.AUTHORIZATION_CODE);
        tokenForm.put(OAuth2Constants.CLIENT_ID, cfg.clientId());
        tokenForm.put(OAuth2Constants.CLIENT_SECRET, cfg.clientSecret());
        tokenForm.put(OAuth2Constants.CODE, authorizationCode);

        return postFormJson(http, tokenUrl, tokenForm);
    }

    public static AccessToken parseAccessToken(String accessTokenStr) throws Exception {
        return new JWSInput(accessTokenStr).readJsonContent(AccessToken.class);
    }

    public static String describeResponseFormat(RequestObject requestObject) {
        if (requestObject.getPresentationDefinition() != null) {
            return "presentation-exchange";
        }
        if (requestObject.getDcqlQuery() != null) {
            return "dcql";
        }
        return "unknown";
    }

    public static String presentScenario(DemoConfig cfg, CredentialScenario scenario, RequestObject requestObject)
            throws Exception {
        String sdJwt = buildSdJwtCredential(cfg, scenario);
        JWK holderKey = loadJwk(Path.of(cfg.holderJwkPath()));
        return presentSdJwt(sdJwt, requestObject.getNonce(), requestObject.getClientId(), holderKey);
    }

    public static void submitPresentation(HttpClient http, RequestObject requestObject, String vpToken) throws Exception {
        Map<String, String> responseForm = new LinkedHashMap<>();

        if (requestObject.getPresentationDefinition() != null) {
            PresentationSubmission submission = buildPresentationSubmission(requestObject.getPresentationDefinition());
            responseForm.put(ResponseObject.VP_TOKEN_KEY, vpToken);
            responseForm.put(
                    ResponseObject.PRESENTATION_SUBMISSION_KEY, JsonSerialization.writeValueAsString(submission));
        } else if (requestObject.getDcqlQuery() != null) {
            DcqlQuery query = requestObject.getDcqlQuery();
            Credential credential = query.getCredentials().getFirst();
            Map<String, List<String>> vpTokenMap = Map.of(credential.getId(), List.of(vpToken));
            responseForm.put(ResponseObject.VP_TOKEN_KEY, JsonSerialization.writeValueAsString(vpTokenMap));
        } else {
            throw new IllegalStateException(
                    "Request object contains neither presentation_definition nor dcql_query");
        }

        responseForm.put(ResponseObject.STATE_KEY, requestObject.getState());
        postForm(http, requestObject.getResponseUri(), responseForm);
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

    private static String buildSdJwtCredential(DemoConfig cfg, CredentialScenario scenario) throws Exception {
        JWK issuerJwk = loadJwk(Path.of(cfg.issuerJwkPath()));
        JWK holderPublicJwk = loadJwk(Path.of(cfg.holderJwkPath()));
        KeyWrapper issuerKeyWrapper = getRsaKeyWrapper(issuerJwk);
        SignatureSignerContext issuerSigner = new AsymmetricSignatureSignerContext(issuerKeyWrapper);

        long now = Time.currentTime();
        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put(OAuth2Constants.ISSUER, cfg.issuer());
        claimSet.put("vct", cfg.vct());
        claimSet.put(OAuth2Constants.USERNAME, scenario.username(cfg));
        claimSet.put("iat", now);
        claimSet.put("exp", now + scenario.expirationOffsetSeconds());

        ObjectNode cnf = JsonSerialization.mapper.createObjectNode();
        cnf.set("jwk", JsonSerialization.mapper.valueToTree(stripEcPrivateKey(holderPublicJwk)));
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
            throw new IllegalStateException(
                    "GET " + url + " failed: " + response.statusCode() + " -> " + response.body());
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
            throw new IllegalStateException(
                    "POST " + url + " failed: " + response.statusCode() + " -> " + response.body());
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
            throw new IllegalStateException(
                    "POST " + url + " failed: " + response.statusCode() + " -> " + response.body());
        }
        return JsonSerialization.readValue(response.body(), JsonNode.class);
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

    public record DemoConfig(
            String baseUrl,
            String realm,
            String clientId,
            String clientSecret,
            String aliceUsername,
            String bobUsername,
            String unknownUsername,
            String vct,
            String issuer,
            String issuerJwkPath,
            String holderJwkPath) {

        public static DemoConfig fromEnv() {
            String baseUrl = env("DEMO_BASE_URL", "http://localhost:18080");
            String realm = env("DEMO_REALM", "oid4vp-demo");
            String clientId = env("DEMO_CLIENT_ID", "test-app");
            String clientSecret = env("DEMO_CLIENT_SECRET", "password");
            String aliceUsername = env("DEMO_ALICE_USERNAME", "alice@localhost");
            String bobUsername = env("DEMO_BOB_USERNAME", "bob@localhost");
            String unknownUsername = env("DEMO_UNKNOWN_USERNAME", "mallory@localhost");
            String vct = env("DEMO_VCT", "https://credentials.example.com/identity_credential");
            String issuerJwk = env("DEMO_ISSUER_JWK", "demo/keys/keycloak.json");
            String holderJwk = env("DEMO_HOLDER_JWK", "demo/keys/user-wallet-key.json");
            String issuer = baseUrl + "/realms/" + realm;

            return new DemoConfig(
                    baseUrl,
                    realm,
                    clientId,
                    clientSecret,
                    aliceUsername,
                    bobUsername,
                    unknownUsername,
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

    public enum CredentialScenario {
        VALID_ALICE(
                "1",
                "Valid credential issued to Alice",
                "Expected result: authentication succeeds for Alice"),
        VALID_BOB(
                "2",
                "Valid credential issued to Bob",
                "Expected result: authentication succeeds for Bob"),
        UNKNOWN_USER(
                "3",
                "Valid credential issued to an unknown user",
                "Expected result: presentation is accepted, user lookup fails"),
        INVALID_ALICE(
                "4",
                "Invalid credential issued to Alice (expired)",
                "Expected result: credential validation fails");

        private final String choice;
        private final String label;
        private final String outcome;

        CredentialScenario(String choice, String label, String outcome) {
            this.choice = choice;
            this.label = label;
            this.outcome = outcome;
        }

        public String choice() {
            return choice;
        }

        public String label() {
            return label;
        }

        public String outcome() {
            return outcome;
        }

        public String username(DemoConfig cfg) {
            return switch (this) {
                case VALID_ALICE, INVALID_ALICE -> cfg.aliceUsername();
                case VALID_BOB -> cfg.bobUsername();
                case UNKNOWN_USER -> cfg.unknownUsername();
            };
        }

        public long expirationOffsetSeconds() {
            return switch (this) {
                case INVALID_ALICE -> -30;
                default -> ISSUER_SIGNED_JWT_LIFESPAN_SECS;
            };
        }

        public static CredentialScenario fromChoice(String choice) {
            for (CredentialScenario scenario : values()) {
                if (scenario.choice.equalsIgnoreCase(choice)) {
                    return scenario;
                }
            }
            return null;
        }
    }

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
