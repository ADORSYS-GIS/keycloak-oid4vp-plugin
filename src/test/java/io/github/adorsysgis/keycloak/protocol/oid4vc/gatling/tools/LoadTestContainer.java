package io.github.adorsysgis.keycloak.protocol.oid4vc.gatling.tools;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.BaseKeycloakTest.TEST_REALM_NAME;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.KeycloakTestContainer.JmxKeycloakContainer.JMX_PORT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPBaseUserAuthEndpointTest.TEST_REALM_OID4VP_AUTH_CONFIG_ID;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.ENFORCE_REVOCATION_STATUS_CONFIG;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.PROFILES_CONFIG;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.KeycloakTestContainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.AuthenticationProfileSamples;
import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import javax.management.remote.JMXServiceURL;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.testcontainers.shaded.org.awaitility.Awaitility;
import org.testcontainers.shaded.org.awaitility.core.ConditionTimeoutException;

/**
 * Manages the singleton Testcontainers Keycloak instance used by the Gatling load-test simulations.
 *
 * <p>The Keycloak container is booted lazily once per JVM and kept running for the whole Gatling
 * run; it is torn down by the Testcontainers Ryuk reaper at JVM exit. JMX is enabled on a fixed
 * port so the container's JVM heap can be sampled during the run.
 */
public final class LoadTestContainer {

    private static final String JMX_JAVA_OPTS = """
            -Dcom.sun.management.jmxremote \
            -Dcom.sun.management.jmxremote.port={jmxPort} \
            -Dcom.sun.management.jmxremote.rmi.port={jmxPort} \
            -Dcom.sun.management.jmxremote.authenticate=false \
            -Dcom.sun.management.jmxremote.ssl=false \
            -Dcom.sun.management.jmxremote.local.only=false \
            -Djava.rmi.server.hostname=localhost \
            """.replace("{jmxPort}", String.valueOf(JMX_PORT));

    private static KeycloakContainer keycloak;

    private LoadTestContainer() {}

    /**
     * Starts a singleton Keycloak container.
     */
    public static synchronized KeycloakContainer keycloak() {
        if (keycloak == null) {
            // Because the container binds a fixed JMX host port, and each forked Gatling simulation runs
            // in its own JVM with its own container, this blocks until the previous JVM's container has fully
            // released that port before starting.
            PortGate.waitForPortFree(JMX_PORT);

            keycloak = KeycloakTestContainer.createJmx(List.of("/realms/test-realm.json"))
                    .withEnv("KC_LOG_LEVEL", "INFO")
                    .withEnv("JAVA_OPTS_APPEND", "-Xmx512m " + JMX_JAVA_OPTS);

            keycloak.start();
        }

        return keycloak;
    }

    /**
     * Returns test realm base URL
     */
    public static String getRealmBaseUrl() {
        Objects.requireNonNull(keycloak());
        String serverUrl = keycloak.getAuthServerUrl();
        return KeycloakUriBuilder.fromUri(serverUrl)
                .path("/realms/{realm}")
                .build(TEST_REALM_NAME)
                .toString();
    }

    /**
     * Returns the JMX service URL to read the Keycloak JVM heap
     */
    public static JMXServiceURL getJmxServiceUrl() {
        Objects.requireNonNull(keycloak());
        try {
            return new JMXServiceURL(String.format("service:jmx:rmi:///jndi/rmi://localhost:%d/jmxrmi", JMX_PORT));
        } catch (Exception e) {
            throw new IllegalStateException("Invalid JMX service URL", e);
        }
    }

    /**
     * Installs the given authentication profile onto the OID4VP authenticator config so the
     * {@code /request} endpoint accepts its {@code profile_id}.
     */
    public static void installAuthProfile(AuthenticationProfileSamples.ProfileSample profile) {
        Objects.requireNonNull(keycloak());
        var auth = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME).flows();
        var config = auth.getAuthenticatorConfig(TEST_REALM_OID4VP_AUTH_CONFIG_ID);

        config.getConfig().put(PROFILES_CONFIG, profile.json());
        config.getConfig().put(ENFORCE_REVOCATION_STATUS_CONFIG, Boolean.FALSE.toString());

        auth.updateAuthenticatorConfig(config.getId(), config);
    }

    /**
     * Organizes logic to wait for ports to become free.
     */
    private static final class PortGate {

        /** How long to keep waiting for the port to be released before giving up. */
        private static final Duration RELEASE_TIMEOUT = Duration.ofMinutes(2);
        /** How long to sleep between attempts to bind the port. */
        private static final Duration RELEASE_POLL = Duration.ofMillis(500);

        private PortGate() {}

        /**
         * Blocks until the port is free.
         */
        public static void waitForPortFree(int port) {
            try {
                Awaitility.await("port " + port + " to become free")
                        .atMost(RELEASE_TIMEOUT)
                        .pollInterval(RELEASE_POLL)
                        .until(() -> isPortFree(port));
            } catch (ConditionTimeoutException e) {
                throw new IllegalStateException(
                        String.format("Port %d was not released within %d s", port, RELEASE_TIMEOUT.toSeconds()), e);
            }
        }

        /**
         * Returns {@code true} if nothing is listening on the given TCP host port.
         */
        private static boolean isPortFree(int port) {
            try (ServerSocket ignored = new ServerSocket(port)) {
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }
}
