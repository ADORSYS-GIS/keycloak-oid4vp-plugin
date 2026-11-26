package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/** SPI wiring for EUDI Hub Organization API clients. */
public class EudiHubClientSpi implements Spi {

    public static final String NAME = "eudi-hub-http-client";

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return EudiHubClientProvider.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return EudiHubClientProviderFactory.class;
    }
}
