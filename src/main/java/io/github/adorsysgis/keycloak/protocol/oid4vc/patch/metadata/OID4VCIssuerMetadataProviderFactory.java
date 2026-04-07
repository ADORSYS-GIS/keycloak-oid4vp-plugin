package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.metadata;

import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.issuance.OID4VCIssuerWellKnownProviderFactory;
import org.keycloak.wellknown.WellKnownProvider;

public class OID4VCIssuerMetadataProviderFactory extends OID4VCIssuerWellKnownProviderFactory {

    @Override
    public int getPriority() {
        return super.getPriority() + 1000;
    }

    @Override
    public WellKnownProvider create(KeycloakSession session) {
        return new OID4VCIssuerMetadataProvider(session);
    }
}
