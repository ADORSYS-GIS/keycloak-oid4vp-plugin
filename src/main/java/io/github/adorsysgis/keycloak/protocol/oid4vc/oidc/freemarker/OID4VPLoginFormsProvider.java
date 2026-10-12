package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.AuthContextBean;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Locale;
import java.util.Properties;
import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.Theme;
import org.keycloak.utils.StringUtil;

public class OID4VPLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    private static final Logger logger = Logger.getLogger(OID4VPLoginFormsProvider.class);

    private final OID4VPUserAuthEndpoint oid4vp;

    public OID4VPLoginFormsProvider(KeycloakSession session) {
        super(session);
        var factory = new OID4VPUserAuthEndpointFactory();
        this.oid4vp = (OID4VPUserAuthEndpoint) factory.create(session);
    }

    /**
     * Redirect a nested presentation straight to the wallet. A missing wallet link still renders the
     * login page so the configuration error can be shown.
     */
    @Override
    protected Response createResponse(LoginFormsPages page) {
        if (page == LoginFormsPages.LOGIN) {
            URI walletUri = walletLocation(
                    new OID4VPUserAuthBean(session, authenticationSession, this.actionUri, oid4vp));
            if (walletUri != null) {
                logger.debugf("Redirecting presentation during issuance to the wallet");
                return Response.status(Response.Status.FOUND)
                        .location(walletUri)
                        .header(HttpHeaders.CACHE_CONTROL, "no-store, must-revalidate, max-age=0")
                        .build();
            }
        }
        return super.createResponse(page);
    }

    /**
     * Wallet URI for a nested presentation, or {@code null} when the login page must still be rendered.
     */
    static URI walletLocation(OID4VPUserAuthBean bean) {
        if (bean == null || !bean.isPresentationDuringIssuance()) {
            return null;
        }
        AuthContextBean context = bean.getAuthContext();
        if (context == null || context.getError() || StringUtil.isBlank(context.getAuthReqLink())) {
            return null;
        }
        return URI.create(context.getAuthReqLink());
    }

    @Override
    protected void createCommonAttributes(
            Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);

        // Inject OID4VP specific attributes
        this.attributes.put("oid4vp", new OID4VPUserAuthBean(session, authenticationSession, this.actionUri, oid4vp));
        logger.debugf("Injected OID4VPUserAuthBean into login form attributes for realm %s", realm.getName());
    }
}
