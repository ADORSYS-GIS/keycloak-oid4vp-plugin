package de.adorsys.gis.keycloak.protocol.oid4vc.oidc.freemarker;

import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.Theme;

import java.net.URI;
import java.util.Locale;
import java.util.Properties;

public class OID4VPLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    private static final Logger logger = Logger.getLogger(OID4VPLoginFormsProvider.class);

    public OID4VPLoginFormsProvider(KeycloakSession session) {
        super(session);

    }

    @Override
    protected void createCommonAttributes(
            Theme theme, Locale locale, Properties messagesBundle,
            UriBuilder baseUriBuilder, LoginFormsPages page
    ) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);
        URI baseUri = baseUriBuilder.build();
        // Inject OID4VP specific attributes
        this.attributes.put("oid4vp", new OID4VPUserAuthBean(session, realm, baseUri));
        logger.debugf("Injected OID4VPUserAuthBean into login form attributes for realm %s", realm.getName());
    }
}
