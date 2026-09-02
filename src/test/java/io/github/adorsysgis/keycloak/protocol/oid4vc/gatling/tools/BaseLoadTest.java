package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools;

import static io.gatling.javaapi.core.CoreDsl.bodyString;
import static io.gatling.javaapi.core.CoreDsl.constantConcurrentUsers;
import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.global;
import static io.gatling.javaapi.core.CoreDsl.jsonPath;
import static io.gatling.javaapi.core.CoreDsl.rampConcurrentUsers;
import static io.gatling.javaapi.http.HttpDsl.http;
import static io.gatling.javaapi.http.HttpDsl.status;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_CLIENT_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_REALM_NAME;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_USER;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_USER_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest.TRANSACTION_ID_PARAM;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseKeycloakTest.getQueryParam;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;
import static org.keycloak.protocol.oidc.OIDCLoginProtocol.REQUEST_URI_PARAM;

import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.PopulationBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Session;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import jakarta.ws.rs.core.MediaType;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.apache.http.HttpStatus;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.util.JsonSerialization;

/**
 * Shared wiring for the Gatling load-test simulations.
 *
 * <p>Exposes the framework and small helpers that mirror the steps of the integration
 * tests in {@code OID4VPUserAuthEndpointTest}.
 *
 * <p>The shared Testcontainers Keycloak setup lives in {@link LoadTestContainer}.
 */
public final class BaseLoadTest {

    /** JVM system property to configure the peak number of concurrent virtual users. */
    public static final String VIRTUAL_USERS_PROPERTY = "gatling.virtualUsers";
    /** JVM system property to configure the ramp-up duration in seconds. */
    public static final String RAMP_DURATION_PROPERTY = "gatling.rampDurationSeconds";
    /** JVM system property to configure the steady-state duration in seconds. */
    public static final String STEADY_DURATION_PROPERTY = "gatling.steadyDurationSeconds";

    public static final int DEFAULT_VIRTUAL_USERS = 30;
    public static final Duration RAMP_DURATION = Duration.ofSeconds(15);
    public static final Duration STEADY_DURATION = Duration.ofSeconds(60);

    static {
        CryptoIntegration.init(BaseLoadTest.class.getClassLoader());
    }

    private BaseLoadTest() {}

    /**
     * Shared HTTP protocol for simulations.
     */
    public static HttpProtocolBuilder httpProtocol() {
        return http.baseUrl(LoadTestContainer.getRealmBaseUrl())
                .acceptHeader(MediaType.APPLICATION_JSON)
                .contentTypeHeader(MediaType.APPLICATION_FORM_URLENCODED);
    }

    /**
     * Shared closed injection profile: ramps virtual users from 1 to {@link #virtualUsers()} over
     * {@link #rampDuration()}, then holds them constant for {@link #steadyDuration()}.
     */
    public static PopulationBuilder inject(ScenarioBuilder flow) {
        int users = virtualUsers();
        return flow.injectClosed(
                rampConcurrentUsers(1).to(users).during(rampDuration()),
                constantConcurrentUsers(users).during(steadyDuration()));
    }

    /**
     * Peak number of concurrent virtual users, read from the {@value #VIRTUAL_USERS_PROPERTY} system
     * property (set at test start, e.g. {@code mvn gatling:test -Dgatling.virtualUsers=50}) or the
     * {@link #DEFAULT_VIRTUAL_USERS} default.
     */
    public static int virtualUsers() {
        return Integer.parseInt(System.getProperty(VIRTUAL_USERS_PROPERTY, String.valueOf(DEFAULT_VIRTUAL_USERS)));
    }

    /**
     * Duration of the ramp-up phase, read from the {@value #RAMP_DURATION_PROPERTY} system property
     * (seconds, e.g. {@code mvn gatling:test -Dgatling.rampDurationSeconds=5}) or the
     * {@link #RAMP_DURATION} default.
     */
    public static Duration rampDuration() {
        return Duration.ofSeconds(
                Long.parseLong(System.getProperty(RAMP_DURATION_PROPERTY, String.valueOf(RAMP_DURATION.toSeconds()))));
    }

    /**
     * Duration of the steady phase, read from the {@value #STEADY_DURATION_PROPERTY} system property
     * (seconds, e.g. {@code mvn gatling:test -Dgatling.steadyDurationSeconds=30}) or the
     * {@link #STEADY_DURATION} default.
     */
    public static Duration steadyDuration() {
        return Duration.ofSeconds(Long.parseLong(
                System.getProperty(STEADY_DURATION_PROPERTY, String.valueOf(STEADY_DURATION.toSeconds()))));
    }

    /**
     * Applies shared performance and correctness assertions to simulations: 95th percentile
     * response time under 3s, zero failures, and at least 100 requests executed.
     */
    public static void assertions(Simulation.SetUp setUp) {
        setUp.assertions(
                global().responseTime().percentile3().lt(3000),
                global().failedRequests().count().is(0L),
                global().allRequests().count().gt(100L));
    }

    /**
     * Builds the Gatling chain shared by both simulations: request an authorization request
     * (optionally for a named authentication profile), resolve the signed request object, parse it,
     * run the credential-specific {@code buildVpTokenStep} (which must set {@code vpTokenJson} on the
     * session), post the authorization response, check the status and redeem the authorization code.
     *
     * <p>The steps are built as named sections (in chronological order) and chained concisely at
     * the end.
     */
    public static ChainBuilder authFlow(String profileId, ChainBuilder buildVpTokenStep) {
        ChainBuilder prepareAuthentication = exec(session -> {
            String codeVerifier = PkceUtils.generateCodeVerifier();
            String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            return TestSession.of(session)
                    .codeVerifier(codeVerifier)
                    .codeChallenge(codeChallenge)
                    .toSession();
        });

        ChainBuilder initiateAuthentication = exec(http("request authorization")
                .get("/oid4vp-auth/request")
                .queryParam(OAuth2Constants.CLIENT_ID, TEST_CLIENT_ID)
                .queryParam(OID4VPUserAuthEndpoint.PROFILE_ID_PARAM, profileId)
                .queryParam(OAuth2Constants.CODE_CHALLENGE, session -> TestSession.of(session)
                        .codeChallenge())
                .queryParam(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)
                .check(status().is(HttpStatus.SC_OK))
                .check(jsonPath("$.authorization_request").saveAs(TestSession.AUTH_REQUEST))
                .check(jsonPath("$.transaction_id").saveAs(TestSession.TRANSACTION_ID)));

        ChainBuilder resolveRequestObject = exec(session -> {
                    String authRequest = TestSession.of(session).authRequest();
                    return TestSession.of(session)
                            .requestUri(getQueryParam(authRequest, REQUEST_URI_PARAM))
                            .toSession();
                })
                .exec(http("resolve signed request object")
                        .get(session -> TestSession.of(session).requestUri())
                        .check(status().is(HttpStatus.SC_OK))
                        .check(bodyString().saveAs(TestSession.SIGNED_REQUEST_OBJECT)))
                .exec(session -> {
                    try {
                        String requestObjectJwt =
                                Objects.requireNonNull(TestSession.of(session).signedRequestObject());
                        RequestObject requestObject =
                                new JWSInput(requestObjectJwt).readJsonContent(RequestObject.class);
                        return TestSession.of(session)
                                .requestObject(requestObject)
                                .toSession();
                    } catch (JWSInputException e) {
                        throw new RuntimeException(e);
                    }
                });

        ChainBuilder postAuthorizationResponse = exec(http("post authorization response")
                .post(session -> TestSession.of(session).requestObject().getResponseUri())
                .formParam(ResponseObject.VP_TOKEN_KEY, session -> TestSession.of(session)
                        .vpTokenJson())
                .formParam(
                        ResponseObject.STATE_KEY,
                        session -> TestSession.of(session).requestObject().getState())
                .check(status().is(HttpStatus.SC_OK)));

        ChainBuilder checkAuthStatus = exec(http("check auth status")
                .get(session -> "/oid4vp-auth/status/" + TestSession.of(session).transactionId())
                .check(status().is(HttpStatus.SC_OK)));

        ChainBuilder redeemAuthCode = exec(http("redeem authorization code")
                .post("/oid4vp-auth/code")
                .formParam(
                        TRANSACTION_ID_PARAM, session -> TestSession.of(session).transactionId())
                .formParam(OAuth2Constants.CODE_VERIFIER, session -> TestSession.of(session)
                        .codeVerifier())
                .check(status().is(HttpStatus.SC_OK))
                .check(jsonPath("$.authorization_code").exists()));

        return prepareAuthentication
                .exec(initiateAuthentication)
                .exec(resolveRequestObject)
                .exec(buildVpTokenStep)
                .exec(postAuthorizationResponse)
                .exec(checkAuthStatus)
                .exec(redeemAuthCode);
    }

    public static String presentSdJwt(RequestObject requestObject) {
        try {
            SdJwtVPTestUtils utils = new SdJwtVPTestUtils(LoadTestContainer.keycloak(), TEST_REALM_NAME);
            String sdJwt = utils.requestSdJwtCredential(CREDENTIAL_TYPES_CONFIG_DEFAULT, TEST_USER);
            return utils.presentSdJwt(
                    sdJwt, requestObject.getNonce(), requestObject.getClientId(), SdJwtVPTestUtils.getUserJwk());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String presentMdoc(RequestObject requestObject) {
        try {
            Map<String, Object> mdocClaims = Map.of(
                    MdocBaseTest.NAMESPACE,
                    Map.of(JsonWebToken.SUBJECT, TEST_USER_ID, OAuth2Constants.USERNAME, TEST_USER));
            return MdocBaseTest.buildMdocVpToken(requestObject, mdocClaims, MdocBaseTest.DOC_TYPE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String buildVpToken(RequestObject requestObject, Map<CredentialFormat, String> credentialMap) {
        Map<String, List<String>> vpToken = credentialMap.entrySet().stream()
                .map(entry -> {
                    var credentialQuery = findCredentialQuery(requestObject, entry.getKey());
                    if (credentialQuery == null) {
                        return null;
                    }

                    return Map.entry(credentialQuery.getId(), List.of(entry.getValue()));
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));

        return JsonSerialization.valueAsString(vpToken);
    }

    private static Credential findCredentialQuery(RequestObject requestObject, CredentialFormat credentialFormat) {
        DcqlQuery dcqlQuery = requestObject.getDcqlQuery();
        if (dcqlQuery == null || dcqlQuery.getCredentials() == null) {
            return null;
        }

        return dcqlQuery.getCredentials().stream()
                .filter(c -> credentialFormat.getValue().equals(c.getFormat()))
                .findFirst()
                .orElse(null);
    }

    /**
     * Typed accessor decorator over the Gatling {@link Session}, centralizing every key read/written
     * by the load-test scenarios.
     *
     * <p>Gatling's {@link Session} is immutable: each setter returns a new {@code TestSession}
     * wrapping the updated session; call {@link #toSession()} to obtain the raw session for the
     * chain lambdas.
     */
    public static final class TestSession {

        public static final String CODE_VERIFIER = "codeVerifier";
        public static final String CODE_CHALLENGE = "codeChallenge";
        public static final String AUTH_REQUEST = "authRequest";
        public static final String TRANSACTION_ID = "transactionId";
        public static final String REQUEST_URI = "requestUri";
        public static final String SIGNED_REQUEST_OBJECT = "signedRequestObject";
        public static final String REQUEST_OBJECT = "requestObject";
        public static final String VP_TOKEN_JSON = "vpTokenJson";

        private final Session session;

        private TestSession(Session session) {
            this.session = session;
        }

        public static TestSession of(Session session) {
            return new TestSession(session);
        }

        public Session toSession() {
            return session;
        }

        public String codeVerifier() {
            return session.getString(CODE_VERIFIER);
        }

        public TestSession codeVerifier(String value) {
            return new TestSession(session.set(CODE_VERIFIER, value));
        }

        public String codeChallenge() {
            return session.getString(CODE_CHALLENGE);
        }

        public TestSession codeChallenge(String value) {
            return new TestSession(session.set(CODE_CHALLENGE, value));
        }

        public String authRequest() {
            return session.getString(AUTH_REQUEST);
        }

        public String transactionId() {
            return session.getString(TRANSACTION_ID);
        }

        public String requestUri() {
            return session.getString(REQUEST_URI);
        }

        public TestSession requestUri(String value) {
            return new TestSession(session.set(REQUEST_URI, value));
        }

        public String signedRequestObject() {
            return session.getString(SIGNED_REQUEST_OBJECT);
        }

        public RequestObject requestObject() {
            return session.get(REQUEST_OBJECT);
        }

        public TestSession requestObject(RequestObject value) {
            return new TestSession(session.set(REQUEST_OBJECT, value));
        }

        public String vpTokenJson() {
            return session.getString(VP_TOKEN_JSON);
        }

        public TestSession vpTokenJson(String value) {
            return new TestSession(session.set(VP_TOKEN_JSON, value));
        }
    }
}
