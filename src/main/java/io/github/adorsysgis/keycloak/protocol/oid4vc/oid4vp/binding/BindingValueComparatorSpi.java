package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding;

import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

/** SPI wiring for pluggable {@link BindingValueComparator} strategies. */
public class BindingValueComparatorSpi implements Spi {

    public static final String NAME = "oid4vp-binding-value-comparator";

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
        return BindingValueComparator.class;
    }

    @Override
    @SuppressWarnings("rawtypes")
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return BindingValueComparatorFactory.class;
    }
}
