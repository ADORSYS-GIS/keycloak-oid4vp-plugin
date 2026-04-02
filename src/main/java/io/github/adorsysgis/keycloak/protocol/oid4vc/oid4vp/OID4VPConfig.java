package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import org.keycloak.Config;

/**
 * Centralized configuration for this plugin, initialized from the {@code oid4vp-auth} provider
 * {@link Config.Scope} in {@link OID4VPUserAuthEndpointFactory}.
 */
public final class OID4VPConfig {

    private static volatile boolean verboseErrors = false;

    private static volatile int certificateCacheMaxSize = ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE;

    private OID4VPConfig() {}

    public static boolean verboseErrors() {
        return verboseErrors;
    }

    /**
     * Configured max entries for the SD-JWT / authorization-request certificate cache
     * ({@code cache-max-size}).
     */
    public static int certificateCacheMaxSize() {
        return certificateCacheMaxSize;
    }

    public static synchronized void init(Config.Scope config) {
        if (config == null) {
            verboseErrors = false;
            certificateCacheMaxSize = ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE;
            ExtendedCertificateUtils.initCache(certificateCacheMaxSize);
            return;
        }

        verboseErrors = config.getBoolean("verbose-errors", false);

        certificateCacheMaxSize = config.getInt("cache-max-size", ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE);
        ExtendedCertificateUtils.initCache(certificateCacheMaxSize);
    }
}
