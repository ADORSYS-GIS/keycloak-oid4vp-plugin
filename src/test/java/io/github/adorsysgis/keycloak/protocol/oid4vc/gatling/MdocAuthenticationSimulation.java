package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling;

import static io.gatling.javaapi.core.CoreDsl.exec;
import static io.gatling.javaapi.core.CoreDsl.scenario;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.MDOC_PRIMARY_PROFILE_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples.mdocPrimary;

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
 * {@code OID4VPUserAuthEndpointTest#shouldAuthenticateSuccessfully_WithMdocPrimaryCredential}.
 *
 * <p>Each virtual user requests an OpenID4VP authorization request for the {@code mdoc-primary}
 * authentication profile, resolves the signed request object, builds a full mDoc primary VP token,
 * posts it back under the {@code primary} credential id, checks the authentication status and
 * redeems the authorization code.
 *
 * <p>The Keycloak container JVM heap is sampled by {@link MemoryMonitor} and written to a CSV in
 * the report directory.
 */
public class MdocAuthenticationSimulation extends Simulation {

    private final HttpProtocolBuilder httpProtocol = BaseLoadTest.httpProtocol();

    private final MemoryMonitor memoryMonitor = new MemoryMonitor(MdocAuthenticationSimulation.class);

    private final ScenarioBuilder flow = scenario("OpenID4VP mDoc authentication")
            .exec(BaseLoadTest.authFlow(MDOC_PRIMARY_PROFILE_ID, buildVpTokenStep()));

    {
        BaseLoadTest.assertions(setUp(BaseLoadTest.inject(flow)).protocols(httpProtocol));
    }

    @Override
    public void before() {
        LoadTestContainer.installAuthProfile(mdocPrimary());
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
            String vpToken = BaseLoadTest.presentMdoc(requestObject);
            String vpTokenJson = BaseLoadTest.buildVpToken(requestObject, Map.of(CredentialFormat.MSO_MDOC, vpToken));
            return ts.vpTokenJson(vpTokenJson).toSession();
        });
    }
}
