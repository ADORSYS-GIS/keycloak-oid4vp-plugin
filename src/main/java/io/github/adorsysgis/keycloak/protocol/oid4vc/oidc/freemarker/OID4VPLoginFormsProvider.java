package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.AuthContextBean;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import org.jboss.logging.Logger;
import org.keycloak.forms.login.LoginFormsPages;
import org.keycloak.forms.login.freemarker.FreeMarkerLoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.theme.Theme;
import org.keycloak.utils.StringUtil;

public class OID4VPLoginFormsProvider extends FreeMarkerLoginFormsProvider {

    private static final Logger logger = Logger.getLogger(OID4VPLoginFormsProvider.class);

    /**
     * Schemes the browser would navigate itself. A wallet redirect must use the configured custom
     * scheme, such as {@code openid4vp} or {@code haip-vp}.
     */
    private static final Set<String> BROWSER_REDIRECT_SCHEMES =
            Set.of("http", "https", "javascript", "data", "file", "blob", "about");

    private final OID4VPUserAuthEndpoint oid4vp;
    private OID4VPUserAuthBean oid4vpUserAuthBean;

    public OID4VPLoginFormsProvider(KeycloakSession session) {
        super(session);
        var factory = new OID4VPUserAuthEndpointFactory();
        this.oid4vp = (OID4VPUserAuthEndpoint) factory.create(session);
    }

    /**
     * Wallet URI for a nested presentation, or {@code null} when the login page must still be rendered.
     * The URI scheme must be a custom wallet scheme. Browser schemes are refused.
     */
    static URI walletLocation(OID4VPUserAuthBean bean) {
        if (bean == null || !bean.isPresentationDuringIssuance()) {
            return null;
        }
        AuthContextBean context = bean.getAuthContext();
        if (context == null || context.getError() || StringUtil.isBlank(context.getAuthReqLink())) {
            return null;
        }
        URI walletUri;
        try {
            walletUri = URI.create(context.getAuthReqLink());
        } catch (IllegalArgumentException e) {
            logger.warnf(e, "Invalid OID4VP authorization request link");
            return null;
        }
        String scheme = walletUri.getScheme();
        if (scheme == null || BROWSER_REDIRECT_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            logger.warnf("Refusing wallet redirect for scheme '%s'", scheme);
            return null;
        }
        return walletUri;
    }

    @Override
    protected void createCommonAttributes(
            Theme theme, Locale locale, Properties messagesBundle, UriBuilder baseUriBuilder, LoginFormsPages page) {
        super.createCommonAttributes(theme, locale, messagesBundle, baseUriBuilder, page);
        OID4VPUserAuthBean bean = oid4vpBean();
        this.attributes.put("oid4vp", bean);
        URI walletUri = walletLocation(bean);
        if (walletUri != null) {
            this.attributes.put("oid4vpWalletHandoff", walletUri.toString());
            if (!cacheControlSet()) {
                setResponseHeader(HttpHeaders.CACHE_CONTROL, "no-store, must-revalidate, max-age=0");
            }
        }
        logger.debugf("Injected OID4VPUserAuthBean into login form attributes for realm %s", realm.getName());
    }

    private boolean cacheControlSet() {
        for (String name : httpResponseHeaders.keySet()) {
            if (HttpHeaders.CACHE_CONTROL.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private OID4VPUserAuthBean oid4vpBean() {
        if (oid4vpUserAuthBean == null) {
            oid4vpUserAuthBean = new OID4VPUserAuthBean(session, authenticationSession, this.actionUri, oid4vp);
        }
        return oid4vpUserAuthBean;
    }
}
