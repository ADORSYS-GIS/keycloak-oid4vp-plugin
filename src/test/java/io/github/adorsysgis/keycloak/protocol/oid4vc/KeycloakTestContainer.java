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

    public static final String TEST_KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.0";
    public static final String TEST_SHADED_PLUGIN_JAR = "target/keycloak-oid4vp-plugin-999.0.0-SNAPSHOT.jar";

    private KeycloakTestContainer() {}

    public static KeycloakContainer create(List<String> realmImports) {
        return create(realmImports, ignored -> {});
    }

    public static KeycloakContainer create(List<String> realmImports, Consumer<String> logConsumer) {
        // noinspection resource
        return new KeycloakContainer(TEST_KEYCLOAK_IMAGE)
                .withImagePullPolicy(PullPolicy.alwaysPull())
                .withProviderLibsFrom(List.of(loadShadedPluginJar()))
                .withProviderClassesFrom("target/classes", "target/test-classes")
                .withFeaturesEnabled("oid4vc-vci", "oid4vc-vci-rest-credential-offer", "oid4vc-vci-preauth-code")
                .withRealmImportFiles(realmImports.toArray(String[]::new))
                .withEnv("JAVA_OPTS_APPEND", "-Xms1g -Xmx2g")
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
}
