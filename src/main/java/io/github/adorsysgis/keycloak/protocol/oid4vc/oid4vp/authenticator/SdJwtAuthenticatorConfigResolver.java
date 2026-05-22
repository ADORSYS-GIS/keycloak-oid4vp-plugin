package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Resolves SD-JWT authenticator configuration from the OpenID4VP authentication flow.
 */
public final class SdJwtAuthenticatorConfigResolver {

    private SdJwtAuthenticatorConfigResolver() {}

    public static AuthenticatorConfigModel resolve(KeycloakSession session) {
        RealmModel realm = session.getContext().getRealm();
        var flow = realm.getFlowByAlias(OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW);
        if (flow == null) {
            throw new IllegalStateException(String.format(
                    "Authentication flow '%s' not found. Such is supposed to be built-in",
                    OID4VPUserAuthEndpointBase.OID4VP_AUTH_FLOW));
        }
        return realm.getAuthenticationExecutionsStream(flow.getId())
                .filter(execution -> execution.getAuthenticator().equals(SdJwtAuthenticatorFactory.PROVIDER_ID))
                .findFirst()
                .map(AuthenticationExecutionModel::getAuthenticatorConfig)
                .map(realm::getAuthenticatorConfigById)
                .orElse(new AuthenticatorConfigModel());
    }
}
