package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

/**
 * Registers the EUDI Hub realm admin extension at {@code /admin/realms/{realm}/eudi-hub}.
 */
public class EudiHubAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String PROVIDER_ID = "eudi-hub";

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new EudiHubAdminResourceProvider();
    }

    @Override
    public void init(Config.Scope config) {
        // Nothing to do.
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // Nothing to do.
    }

    @Override
    public void close() {
        // Nothing to close.
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
