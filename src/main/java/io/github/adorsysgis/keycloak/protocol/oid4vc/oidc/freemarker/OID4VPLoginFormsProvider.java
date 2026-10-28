package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.AuthContextBean;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
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

    /**
     * Reads the anchor href so the wallet URI stays out of the script. The script text is stable, and
     * its hash can be added to a Content-Security-Policy that would otherwise block the handoff.
     */
    public static final String WALLET_HANDOFF_SCRIPT =
            "location.replace(document.getElementById(\"kc-oid4vp-wallet\").href)";

    private static final String WALLET_HANDOFF_SCRIPT_SOURCE = "'sha256-" + sha256(WALLET_HANDOFF_SCRIPT) + "'";
    private static final String CONTENT_SECURITY_POLICY = "Content-Security-Policy";

    private final OID4VPUserAuthEndpoint oid4vp;
    private OID4VPUserAuthBean oid4vpUserAuthBean;

    public OID4VPLoginFormsProvider(KeycloakSession session) {
        super(session);
        var factory = new OID4VPUserAuthEndpointFactory();
        this.oid4vp = (OID4VPUserAuthEndpoint) factory.create(session);
    }

    /**
     * Return a page that opens the wallet. A missing or invalid wallet link still renders the login
     * page so the configuration error can be shown.
     */
    @Override
    protected Response createResponse(LoginFormsPages page) {
        if (page == LoginFormsPages.LOGIN) {
            URI walletUri = walletLocation(oid4vpBean());
            if (walletUri != null) {
                logger.debugf("Returning a wallet handoff page for presentation during issuance");
                return walletRedirect(walletUri, httpResponseHeaders);
            }
        }
        return super.createResponse(page);
    }

    /**
     * HTML page that navigates to the wallet and keeps a visible link when the script cannot run.
     * Copies every header registered through {@code setResponseHeader(...)} except {@code Content-Type}.
     * A supplied Content-Security-Policy is extended with the handoff script hash. {@code Cache-Control:
     * no-store} is added only when the login flow did not set one.
     */
    static Response walletRedirect(URI walletUri, Map<String, String> responseHeaders) {
        Response.ResponseBuilder page = Response.ok(
                        walletHandoffPage(walletUri), MediaType.TEXT_HTML_TYPE.withCharset("UTF-8"))
                .language((String) null);
        boolean cacheControlSet = false;
        if (responseHeaders != null) {
            for (Map.Entry<String, String> header : responseHeaders.entrySet()) {
                if (HttpHeaders.CONTENT_TYPE.equalsIgnoreCase(header.getKey())) {
                    continue;
                }
                String value = header.getValue();
                if (CONTENT_SECURITY_POLICY.equalsIgnoreCase(header.getKey())) {
                    value = allowHandoffScript(value);
                }
                page.header(header.getKey(), value);
                if (HttpHeaders.CACHE_CONTROL.equalsIgnoreCase(header.getKey())) {
                    cacheControlSet = true;
                }
            }
        }
        if (!cacheControlSet) {
            page.header(HttpHeaders.CACHE_CONTROL, "no-store, must-revalidate, max-age=0");
        }
        return page.build();
    }

    static String walletHandoffPage(URI walletUri) {
        return """
                <!DOCTYPE html>
                <html>
                <head><meta charset="utf-8"></head>
                <body>
                <p><a id="kc-oid4vp-wallet" href="%s">Open with a wallet</a></p>
                <script>%s</script>
                </body>
                </html>
                """.formatted(escapeHtml(walletUri.toString()), WALLET_HANDOFF_SCRIPT);
    }

    /**
     * Lets the handoff script run under a policy such as {@code default-src 'none'}. An existing
     * {@code script-src} is extended; a second {@code script-src} would be ignored.
     */
    static String allowHandoffScript(String policy) {
        if (policy.contains(WALLET_HANDOFF_SCRIPT_SOURCE)) {
            return policy;
        }
        int start = directiveStart(policy.toLowerCase(Locale.ROOT), "script-src");
        if (start < 0) {
            String trimmed = policy.stripTrailing();
            String separator = trimmed.isEmpty() || trimmed.endsWith(";") ? "" : ";";
            String prefix = trimmed.isEmpty() ? "" : trimmed + separator + " ";
            return prefix + "script-src " + WALLET_HANDOFF_SCRIPT_SOURCE;
        }
        int end = policy.indexOf(';', start);
        if (end < 0) {
            end = policy.length();
        }
        return policy.substring(0, end) + " " + WALLET_HANDOFF_SCRIPT_SOURCE + policy.substring(end);
    }

    private static int directiveStart(String lowerPolicy, String directive) {
        int from = 0;
        while (from <= lowerPolicy.length() - directive.length()) {
            int found = lowerPolicy.indexOf(directive, from);
            if (found < 0) {
                return -1;
            }
            boolean boundaryBefore = found == 0 || isDirectiveBoundary(lowerPolicy.charAt(found - 1));
            int after = found + directive.length();
            boolean boundaryAfter = after == lowerPolicy.length()
                    || Character.isWhitespace(lowerPolicy.charAt(after))
                    || lowerPolicy.charAt(after) == ';';
            if (boundaryBefore && boundaryAfter) {
                return found;
            }
            from = found + 1;
        }
        return -1;
    }

    private static boolean isDirectiveBoundary(char character) {
        return character == ';' || Character.isWhitespace(character);
    }

    private static String escapeHtml(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
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
