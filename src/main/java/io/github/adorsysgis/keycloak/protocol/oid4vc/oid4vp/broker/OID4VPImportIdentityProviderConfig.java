package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker;

import org.keycloak.models.IdentityProviderModel;

/**
 * Configuration model of the hidden OpenID4VP Plugin Import identity provider.
 *
 * <p>The provider is a configuration and mapping host for user import: it owns the federated
 * identity link namespace (its alias), the sync mode, and the user-attribute mappers. It performs
 * no authorization requests and verifies no presentations; direct login through it is unsupported.
 */
public class OID4VPImportIdentityProviderConfig extends IdentityProviderModel {

    public OID4VPImportIdentityProviderConfig() {}

    public OID4VPImportIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }
}
