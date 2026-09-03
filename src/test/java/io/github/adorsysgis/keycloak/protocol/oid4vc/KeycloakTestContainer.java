package io.github.adorsysgis.keycloak.protocol.oid4vc;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.File;
import java.util.List;
import java.util.function.Consumer;
import org.jboss.logging.Logger;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.MountableFile;

/**
 * Shared Testcontainers configuration for Keycloak integration tests.
 */
public final class KeycloakTestContainer {

    private static final Logger logger = Logger.getLogger(KeycloakTestContainer.class);

    public static final String TEST_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.3";
    public static final String TEST_SHADED_PLUGIN_JAR = "target/keycloak-oid4vp-plugin-999.0.0-SNAPSHOT.jar";

    private KeycloakTestContainer() {}

    public static KeycloakContainer create(List<String> realmImports) {
        return create(realmImports, ignored -> {});
    }

    public static KeycloakContainer create(List<String> realmImports, Consumer<String> logConsumer) {
        return configure(new KeycloakContainer(TEST_KEYCLOAK_IMAGE), realmImports, logConsumer);
    }

    /**
     * Like {@link #create(List)} but binds a fixed host port to the container JMX port so the JVM
     * heap can be sampled remotely via {@link JmxKeycloakContainer#JMX_PORT}.
     */
    public static KeycloakContainer createJmx(List<String> realmImports) {
        return configure(new JmxKeycloakContainer(TEST_KEYCLOAK_IMAGE), realmImports, ignored -> {});
    }

    private static KeycloakContainer configure(
            KeycloakContainer container, List<String> realmImports, Consumer<String> logConsumer) {
        return container
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withProviderLibsFrom(List.of(loadShadedPluginJar()))
                .withProviderClassesFrom("target/classes", "target/test-classes")
                .withFeaturesEnabled("oid4vc-vci", "oid4vc-vci-rest-credential-offer", "oid4vc-vci-preauth-code")
                .withRealmImportFiles(realmImports.toArray(String[]::new))
                .withEnv("KC_SPI_REALM_RESTAPI_EXTENSION_OID4VP_AUTH_MANAGED_REALMS", "test-v2")
                .withEnv("KC_SPI_REALM_RESTAPI_EXTENSION_OID4VP_AUTH_VERBOSE_ERRORS", "true")
                .withEnv("KC_LOG_LEVEL", "INFO,io.github.adorsysgis:DEBUG")
                .withCopyToContainer(
                        MountableFile.forHostPath("src/test/resources/truststore.jks"),
                        "/opt/keycloak/conf/truststore.jks")
                .withEnv("KC_SPI_TRUSTSTORE_FILE_FILE", "/opt/keycloak/conf/truststore.jks")
                .withEnv("KC_SPI_TRUSTSTORE_FILE_PASSWORD", "password")
                .withEnv("KC_TLS_HOSTNAME_VERIFIER", "ANY")
                .withLogConsumer(frame -> logConsumer.accept(frame.getUtf8String()));
    }

    private static File loadShadedPluginJar() {
        File shadedJar = new File(TEST_SHADED_PLUGIN_JAR);
        if (!shadedJar.exists()) {
            String message = String.format(
                    "Shaded plugin jar not found: %s. Run './mvnw package -DskipTests' to generate it.",
                    TEST_SHADED_PLUGIN_JAR);
            logger.error(message);
            throw new IllegalStateException(message);
        }
        return shadedJar;
    }

    /**
     * {@link KeycloakContainer} that binds a fixed host port to the container JMX port so the JVM
     * heap can be read via {@code service:jmx:rmi:///jndi/rmi://localhost:<port>/jmxrmi}.
     */
    public static final class JmxKeycloakContainer extends KeycloakContainer {

        public static final int JMX_PORT = 9099;

        JmxKeycloakContainer(String image) {
            super(image);
            addFixedExposedPort(JMX_PORT, JMX_PORT);
        }
    }
}
