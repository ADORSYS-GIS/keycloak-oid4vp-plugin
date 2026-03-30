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

    private static volatile boolean verboseErrors = false;

    private OID4VPConfig() {}

    public static boolean verboseErrors() {
        return verboseErrors;
    }

    public static synchronized void init(Config.Scope config) {
        if (config == null) {
            verboseErrors = false;
            return;
        }

        boolean enabled = config.getBoolean("verbose-errors", false) || config.getBoolean("verboseErrors", false);
        verboseErrors = verboseErrors || enabled;
    }
}
