package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import java.util.Arrays;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.utils.StringUtil;

/**
 * Centralized configuration for this plugin, initialized from the {@code oid4vp-auth} provider
 * {@link Config.Scope} in {@link OID4VPUserAuthEndpointFactory}.
 */
public final class OID4VPConfig {

    /**
     * Config key for the comma-separated list of realm names for which the plugin manages
     * lifecycle: auto-creating the {@code oid4vp auth} authentication flow on new realms and
     * running schema/config migrations on existing ones. By default, the list is empty and no
     * realm is managed.
     */
    public static final String MANAGED_REALMS_CONFIG = "managed-realms";

    /**
     * Config key for the verbose-error-response toggle.
     */
    public static final String VERBOSE_ERRORS_CONFIG = "verbose-errors";

    /**
     * Config key for the certificate cache size.
     * Or max entries for the authorization-request certificate cache.
     */
    public static final String CACHE_MAX_SIZE_CONFIG = "cache-max-size";

    private final boolean verboseErrors;
    private final int certificateCacheMaxSize;
    private final List<String> autoCreateAuthFlowRealms;

    public OID4VPConfig(Config.Scope config) {
        this.autoCreateAuthFlowRealms = config == null ? List.of() : parseRealmList(config.get(MANAGED_REALMS_CONFIG));
        this.verboseErrors = config != null && config.getBoolean(VERBOSE_ERRORS_CONFIG, false);
        this.certificateCacheMaxSize = config == null
                ? ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE
                : config.getInt(CACHE_MAX_SIZE_CONFIG, ExtendedCertificateUtils.DEFAULT_MAX_CACHE_SIZE);
    }

    /**
     * Returns whether the {@code oid4vp auth} flow should be auto-created for the given realm.
     * Matches when the configured list contains the realm's own name.
     */
    public boolean shouldAutoCreateAuthFlowFor(String realmName) {
        if (StringUtil.isBlank(realmName)) {
            return false;
        }

        return autoCreateAuthFlowRealms.contains(realmName);
    }

    public int cacheMaxSize() {
        return certificateCacheMaxSize;
    }

    public boolean verboseErrors() {
        return verboseErrors;
    }

    private static List<String> parseRealmList(String raw) {
        if (raw == null) {
            return List.of();
        }

        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(StringUtil::isNotBlank)
                .toList();
    }
}
