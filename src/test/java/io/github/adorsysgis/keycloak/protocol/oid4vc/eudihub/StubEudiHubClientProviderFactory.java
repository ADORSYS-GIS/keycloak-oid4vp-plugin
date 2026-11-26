package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.models.KeycloakSession;

/** Overrides the HTTP provider factory with the in-process EUDI Hub stub in integration tests. */
public final class StubEudiHubClientProviderFactory extends EudiHubHttpClientProviderFactory {

    @Override
    public int order() {
        return super.order() + 10;
    }

    @Override
    public EudiHubClientProvider create(KeycloakSession session) {
        return new StubEudiHubClientProvider();
    }
}
