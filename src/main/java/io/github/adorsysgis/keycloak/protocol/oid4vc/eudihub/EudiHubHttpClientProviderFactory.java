package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/** Default HTTP-backed EUDI Hub client provider factory. */
public class EudiHubHttpClientProviderFactory implements EudiHubClientProviderFactory {

    public static final String PROVIDER_ID = "default";

    @Override
    public EudiHubClientProvider create(KeycloakSession session) {
        return new DefaultEudiHubClientProvider(session);
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
