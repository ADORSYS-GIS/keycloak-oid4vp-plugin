package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import org.keycloak.Config;

/**
 * Centralized configuration for this plugin, initialized from the {@code oid4vp-auth} provider
 * {@link Config.Scope} in {@link OID4VPUserAuthEndpointFactory}.
 */
public final class OID4VPConfig {

    private final boolean verboseErrors;
    private final int certificateCacheMaxSize;

    /**
     * Configured max entries for the SD-JWT / authorization-request certificate cache
     * ({@code cache-max-size}).
     */
    public int cacheMaxSize() {
        return certificateCacheMaxSize;
    }

    public boolean verboseErrors() {
        return verboseErrors;
    }

    public OID4VPConfig(Config.Scope config) {
        this.verboseErrors = config != null && config.getBoolean("verbose-errors", false);
        this.certificateCacheMaxSize = config == null
                ? ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE
                : config.getInt("cache-max-size", ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE);
    }
}
