package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.AuthContextBean;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Locale;
import java.util.Map;
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
     * Redirect a nested presentation straight to the wallet. A missing or invalid wallet link still
     * renders the login page so the configuration error can be shown.
     */
    @Override
    protected Response createResponse(LoginFormsPages page) {
        if (page == LoginFormsPages.LOGIN) {
            URI walletUri = walletLocation(oid4vpBean());
            if (walletUri != null) {
                logger.debugf("Redirecting presentation during issuance to the wallet");
                return walletRedirect(walletUri, httpResponseHeaders);
            }
        }
        return super.createResponse(page);
    }

    /**
     * 302 to the wallet. Copies every header registered through {@code setResponseHeader(...)}.
     * Template rendering also sets an HTML content type, language, and body; those stay off this
     * redirect. {@code Cache-Control: no-store} is added only when the login flow did not set one.
     */
    static Response walletRedirect(URI walletUri, Map<String, String> responseHeaders) {
        Response.ResponseBuilder redirect =
                Response.status(Response.Status.FOUND).location(walletUri);
        boolean cacheControlSet = false;
        if (responseHeaders != null) {
            for (Map.Entry<String, String> header : responseHeaders.entrySet()) {
                redirect.header(header.getKey(), header.getValue());
                if (HttpHeaders.CACHE_CONTROL.equalsIgnoreCase(header.getKey())) {
                    cacheControlSet = true;
                }
            }
        }
        if (!cacheControlSet) {
            redirect.header(HttpHeaders.CACHE_CONTROL, "no-store, must-revalidate, max-age=0");
        }
        return redirect.build();
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

        // Inject OID4VP specific attributes. Reuse the bean from createResponse so a failed wallet
        // redirect does not start a second authentication transaction.
        this.attributes.put("oid4vp", oid4vpBean());
        logger.debugf("Injected OID4VPUserAuthBean into login form attributes for realm %s", realm.getName());
    }

    private OID4VPUserAuthBean oid4vpBean() {
        if (oid4vpUserAuthBean == null) {
            oid4vpUserAuthBean = new OID4VPUserAuthBean(session, authenticationSession, this.actionUri, oid4vp);
        }
        return oid4vpUserAuthBean;
    }
}
