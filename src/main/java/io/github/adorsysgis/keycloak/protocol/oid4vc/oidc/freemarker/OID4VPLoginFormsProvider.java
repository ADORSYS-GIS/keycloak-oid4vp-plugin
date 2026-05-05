package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import jakarta.ws.rs.core.UriBuilder;
import java.util.Locale;
import java.util.Optional;
import java.util.Properties;
import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.Theme;

public class OID4VPLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    private static final Logger logger = Logger.getLogger(OID4VPLoginFormsProvider.class);

    private final OID4VPUserAuthEndpoint oid4vp;

    public OID4VPLoginFormsProvider(KeycloakSession session) {
        super(session);
        var factory = new OID4VPUserAuthEndpointFactory();
        this.oid4vp = (OID4VPUserAuthEndpoint) factory.create(session);
    }

    @Override
    protected void createCommonAttributes(
            Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);

        // Retrieve the authentication session ID from the current context, if available
        String authSessionId = Optional.ofNullable(authenticationSession)
                .map(OID4VPUserAuthEndpointBase::getAuthSessionId)
                .orElse(null);

        // Inject OID4VP specific attributes
        this.attributes.put("oid4vp", new OID4VPUserAuthBean(session, realm, oid4vp, this.actionUri, authSessionId));
        logger.debugf("Injected OID4VPUserAuthBean into login form attributes for realm %s", realm.getName());
    }
}
