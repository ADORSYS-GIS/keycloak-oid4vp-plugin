package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.matcher;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/** Registers the PID matcher SPI so external matcher providers can be discovered at runtime. */
public class PidMatcherSpi implements Spi {

    public static final String SPI_NAME = "pid-matcher";

    @Override
    public boolean isInternal() {
        return false;
    }

    @Override
    public String getName() {
        return SPI_NAME;
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return PidMatcherProvider.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return PidMatcherProviderFactory.class;
    }
}
