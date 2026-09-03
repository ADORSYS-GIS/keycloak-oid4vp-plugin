package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.DefaultCredentialOfferProviderFactory;

/**
 * Overrides the default credential-offer provider with a higher-priority decorated instance.
 *
 * <p>Remove this factory together with {@link PatchedCredentialOfferProvider} once the fix is part
 * of the supported Keycloak release.
 */
public final class PatchedCredentialOfferProviderFactory extends DefaultCredentialOfferProviderFactory {

    @Override
    public CredentialOfferProvider create(KeycloakSession session) {
        return new PatchedCredentialOfferProvider(super.create(session));
    }

    @Override
    public int order() {
        return super.order() + 9;
    }
}

