package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import org.keycloak.Config;
import org.keycloak.provider.EnvironmentDependentProviderFactory;

/**
 * Interface for all OID4VP related provider factories, constraining them
 * to the appropriate, corresponding feature flag.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public interface OID4VPEnvironmentProviderFactory extends EnvironmentDependentProviderFactory {

    @Override
    default boolean isSupported(Config.Scope config) {
        return true; // The feature is available with the plugin, no specific flag needed
    }
}
