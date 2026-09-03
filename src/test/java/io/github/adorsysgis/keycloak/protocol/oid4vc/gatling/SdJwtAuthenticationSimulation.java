package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling;

import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.scenario;

import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools.BaseLoadTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools.MemoryMonitor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.AuthenticationProfile;
import java.util.Map;

/**
 * Gatling simulation closely mirroring {@code OID4VPUserAuthEndpointTest#shouldAuthenticateSuccessfully_SdJwtWithKid}.
 *
 * <p>Each virtual user requests an OpenID4VP authorization request, resolves the signed request
 * object, builds an SD-JWT credential + key-binding VP token, posts it back, checks the authentication
 * status and redeems the authorization code.
 *
 * <p>The Keycloak container JVM heap is sampled by {@link MemoryMonitor} and written to a CSV in
 * the report directory.
 */
public class SdJwtAuthenticationSimulation extends Simulation {

    private final HttpProtocolBuilder httpProtocol = BaseLoadTest.httpProtocol();

    private final MemoryMonitor memoryMonitor = new MemoryMonitor(SdJwtAuthenticationSimulation.class);

    private final ScenarioBuilder flow = scenario("OpenID4VP SD-JWT authentication")
            .exec(BaseLoadTest.authFlow(AuthenticationProfile.DEFAULT_PROFILE_ID, buildVpTokenStep()));

    {
        BaseLoadTest.assertions(setUp(BaseLoadTest.inject(flow)).protocols(httpProtocol));
    }

    @Override
    public void before() {
        memoryMonitor.start();
    }

    @Override
    public void after() {
        memoryMonitor.stop();
    }

    private ChainBuilder buildVpTokenStep() {
        return exec(session -> {
            BaseLoadTest.TestSession ts = BaseLoadTest.TestSession.of(session);
            RequestObject requestObject = ts.requestObject();
            String vpToken = BaseLoadTest.presentSdJwt(requestObject);
            String vpTokenJson = BaseLoadTest.buildVpToken(requestObject, Map.of(CredentialFormat.SD_JWT_VC, vpToken));
            return ts.vpTokenJson(vpTokenJson).toSession();
        });
    }
}
