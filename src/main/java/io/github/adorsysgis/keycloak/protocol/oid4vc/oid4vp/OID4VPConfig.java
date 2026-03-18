package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import org.keycloak.Config;

/**
 * Centralized configuration for this plugin.
 *
 * <p>Keycloak provider factories receive different {@link Config.Scope} instances depending on the
 * SPI/provider. To keep configuration consistent, we support a global environment variable/system
 * property override, and also allow reading a local provider scope key when available.</p>
 */
public final class OID4VPConfig {

    private static volatile boolean initialized = false;

    private static volatile boolean verboseErrors = false;

    private OID4VPConfig() {}

    public static boolean verboseErrors() {
        return verboseErrors;
    }

    public static synchronized void init(Config.Scope config) {
        if (initialized) {
            return;
        }

        // Global overrides (work well for containers and tests).
        // Examples:
        // - env:  OID4VP_VERBOSE_ERRORS=true
        // - prop: -Doid4vp.verboseErrors=true
        String env = System.getenv("OID4VP_VERBOSE_ERRORS");
        String prop = System.getProperty("oid4vp.verboseErrors");

        if (env != null) {
            verboseErrors = Boolean.parseBoolean(env);
        } else if (prop != null) {
            verboseErrors = Boolean.parseBoolean(prop);
        } else if (config != null) {
            // Local scope fallback for Keycloak SPI configs
            verboseErrors = config.getBoolean("verboseErrors", false);
        } else {
            verboseErrors = false;
        }

        initialized = true;
    }
}

