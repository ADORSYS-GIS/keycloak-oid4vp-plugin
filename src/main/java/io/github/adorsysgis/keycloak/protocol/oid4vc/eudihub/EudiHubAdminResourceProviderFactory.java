package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

/**
 * Registers the EUDI Hub realm admin extension at {@code /admin/realms/{realm}/eudi-hub}.
 *
 * <p>The upstream URL can be overridden with
 * {@code --spi-admin-realm-restapi-extension-eudi-hub-api-url=https://...}. It must use HTTPS.
 */
public class EudiHubAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    public static final String PROVIDER_ID = "eudi-hub";

    private String baseUrl;

    @Override
    public AdminRealmResourceProvider create(KeycloakSession session) {
        return new EudiHubAdminResourceProvider(baseUrl);
    }

    @Override
    public void init(Config.Scope config) {
        baseUrl = EudiHubService.normalizeBaseUrl(config.get("apiUrl", EudiHubService.DEFAULT_BASE_URL));
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
