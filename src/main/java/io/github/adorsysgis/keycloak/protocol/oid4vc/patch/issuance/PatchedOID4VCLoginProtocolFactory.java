package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.OID4VCLoginProtocolFactory;

/**
 * Overrides the default {@link OID4VCLoginProtocolFactory} with a higher priority
 * to provide the {@link PatchedOID4VCIssuerEndpoint}.
 */
public class PatchedOID4VCLoginProtocolFactory extends OID4VCLoginProtocolFactory {

    @Override
    public Object createProtocolEndpoint(KeycloakSession session, EventBuilder event) {
        return new PatchedOID4VCIssuerEndpoint(session);
    }

    @Override
    public int order() {
        return super.order() + 10; // Higher than default -> this factory wins
    }
}
