package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.binding;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Factory for the built-in {@link ExactBindingValueComparator}. */
public class ExactBindingValueComparatorFactory implements BindingValueComparatorFactory {

    public static final String PROVIDER_ID = "exact";

    private final ExactBindingValueComparator provider = new ExactBindingValueComparator();

    @Override
    public BindingValueComparator create(KeycloakSession session) {
        return provider;
    }

    @Override
    public void init(Config.Scope config) {}

    @Override
    public void postInit(KeycloakSessionFactory factory) {}

    @Override
    public void close() {}

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
