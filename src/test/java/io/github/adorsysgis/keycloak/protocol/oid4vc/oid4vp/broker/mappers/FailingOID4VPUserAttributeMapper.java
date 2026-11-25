package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.broker.mappers;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/** Test-only mapper that forces a failure after import or synchronization has started mutating a user. */
public final class FailingOID4VPUserAttributeMapper extends OID4VPUserAttributeMapper {

    public static final String PROVIDER_ID = "test-failing-oid4vp-user-attribute-mapper";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Failing OpenID4VP Attribute Importer (test only)";
    }

    @Override
    public void importNewUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        throw new IllegalStateException("Deliberate post-write mapper failure");
    }

    @Override
    public void updateBrokeredUser(
            KeycloakSession session,
            RealmModel realm,
            UserModel user,
            IdentityProviderMapperModel mapperModel,
            BrokeredIdentityContext context) {
        throw new IllegalStateException("Deliberate linked-user synchronization failure");
    }
}
