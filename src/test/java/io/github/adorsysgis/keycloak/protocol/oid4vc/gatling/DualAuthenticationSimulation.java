package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling;

import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.scenario;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.SDJWT_MDOC_DUAL_PROFILE_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.sdjwtMdocDual;

import io.gatling.javaapi.core.ChainBuilder;
import io.gatling.javaapi.core.ScenarioBuilder;
import io.gatling.javaapi.core.Simulation;
import io.gatling.javaapi.http.HttpProtocolBuilder;
import io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools.BaseLoadTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools.LoadTestContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools.MemoryMonitor;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import java.util.Map;

/**
 * Gatling simulation closely mirroring
 * {@code OID4VPUserAuthEndpointTest#shouldAuthenticateSuccessfully_WithSdJwtPrimaryAndMdocSupporting}.
 *
 * <p>Each virtual user requests an OpenID4VP request for the {@code sdjwt-mdoc-dual} profile, resolves
 * the signed request object, builds an SD-JWT primary VP token and a full mDoc supporting VP token,
 * and posts the combined {@code vp_token} map to complete authentication.
 *
 * <p>The Keycloak container JVM heap is sampled by {@link MemoryMonitor} and written to a CSV in
 * the report directory.
 */
public class DualAuthenticationSimulation extends Simulation {

    private final HttpProtocolBuilder httpProtocol = BaseLoadTest.httpProtocol();

    private final MemoryMonitor memoryMonitor = new MemoryMonitor(DualAuthenticationSimulation.class);

    private final ScenarioBuilder flow = scenario("OpenID4VP SD-JWT + mDoc authentication")
            .exec(BaseLoadTest.authFlow(SDJWT_MDOC_DUAL_PROFILE_ID, buildVpTokenStep()));

    {
        BaseLoadTest.assertions(setUp(BaseLoadTest.inject(flow)).protocols(httpProtocol));
    }

    @Override
    public void before() {
        LoadTestContainer.installAuthProfile(sdjwtMdocDual());
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
            return ts.vpTokenJson(BaseLoadTest.buildVpToken(
                            requestObject,
                            Map.of(
                                    CredentialFormat.SD_JWT_VC, BaseLoadTest.presentSdJwt(requestObject),
                                    CredentialFormat.MSO_MDOC, BaseLoadTest.presentMdoc(requestObject))))
                    .toSession();
        });
    }
}
