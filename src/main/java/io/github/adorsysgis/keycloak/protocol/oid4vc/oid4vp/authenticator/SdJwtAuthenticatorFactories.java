package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;

/**
 * Access to the registered {@link SdJwtAuthenticatorFactory} for a session.
 */
public final class SdJwtAuthenticatorFactories {

    private SdJwtAuthenticatorFactories() {}

    public static SdJwtAuthenticatorFactory getFactory(KeycloakSession session) {
        var providerFactory = session.getKeycloakSessionFactory()
                .getProviderFactory(Authenticator.class, SdJwtAuthenticatorFactory.PROVIDER_ID);
        if (providerFactory instanceof SdJwtAuthenticatorFactory sdJwtAuthenticatorFactory) {
            return sdJwtAuthenticatorFactory;
        }
        return new SdJwtAuthenticatorFactory();
    }

    public static StatusListJwtFetcher createStatusListJwtFetcher(KeycloakSession session) {
        return getFactory(session).createStatusListJwtFetcher(session);
    }
}
