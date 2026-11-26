package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.fgap.AdminPermissionEvaluator;

/**
 * Provides the {@link EudiHubAdminResource} sub-resource for the realm admin API.
 */
public class EudiHubAdminResourceProvider implements AdminRealmResourceProvider {

    @Override
    public Object getResource(
            KeycloakSession session, RealmModel realm, AdminPermissionEvaluator auth, AdminEventBuilder adminEvent) {
        return new EudiHubAdminResource(realm, auth, new EudiHubService(session));
    }

    @Override
    public void close() {
        // Nothing to close.
    }
}
