package de.adorsys.gis.keycloak.protocol.oid4vc.oidc.freemarker;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProviderFactory;
import org.keycloak.models.KeycloakSession;

public class OID4VPLoginFormsProviderFactory extends FreeMarkerLoginFormsProviderFactory {

    @Override
    public LoginFormsProvider create(KeycloakSession session) {
        return new OID4VPLoginFormsProvider(session);
    }
}
