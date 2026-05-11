package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.OID4VPLoginActionsService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.OID4VPLoginActionsServiceFactory;
import jakarta.ws.rs.core.UriBuilder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class OID4VPUserAuthBean {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthBean.class);

    public static final String PARAM_LOGIN_METHOD = "login_method";
    public static final String LOGIN_METHOD_OID4VP = "oid4vp";

    public static final String QR_CODE_IMAGE_FORMAT = "png";
    public static final int QR_CODE_IMAGE_SIZE = 300;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final URI actionUri;
    private final String authSessionId;

    private final OID4VPUserAuthEndpoint oid4vp;
    private AuthContextBean authContextBean;

    public OID4VPUserAuthBean(
            KeycloakSession session,
            RealmModel realm,
            OID4VPUserAuthEndpoint oid4vp,
            URI actionUri,
            String authSessionId) {
        this.session = session;
        this.realm = realm;
        this.oid4vp = oid4vp;
        this.actionUri = actionUri;
        this.authSessionId = authSessionId;
    }

    /**
     * URL to trigger UI view for signing in with a wallet
     */
    public String getLoginUrl() {
        URI currentUri = session.getContext().getUri().getRequestUri();

        // Read client ID
        var params = session.getContext().getUri().getQueryParameters();
        String clientId = params.getFirst(OAuth2Constants.CLIENT_ID);

        // Validate client ID for OpenID4VP login
        try {
            oid4vp.checkClient(clientId);
        } catch (IllegalArgumentException e) {
            logger.debugf("Invalid client ID '%s' in OIDC URL. Not offering option for OpenID4VP login", clientId);
            return null;
        }

        // Build a new URI with the extra query parameter
        return UriBuilder.fromUri(currentUri)
                .replaceQueryParam(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP)
                .build()
                .toString();
    }

    /**
     * URL to continue OIDC flow upon successful OID4VP authentication
     */
    public String getLoginActionUrl() {
        // Overwrite path to point to OID4VPLoginActionsService
        return UriBuilder.fromUri(actionUri)
                .replacePath(null)
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPLoginActionsServiceFactory.PROVIDER_ID)
                .path(OID4VPLoginActionsService.OID4VP_AUTH_LOGIN_PATH)
                .build(realm.getName())
                .toString();
    }

    /**
     * Initiate OID4VP authentication and pass authorization context to UI.
     */
    public AuthContextBean getAuthContext() {
        var params = session.getContext().getUri().getQueryParameters();

        // Skip if OID4VP login method not requested
        String loginMethod = params.getFirst(PARAM_LOGIN_METHOD);
        if (!LOGIN_METHOD_OID4VP.equals(loginMethod)) {
            logger.debugf("OpenID4VP login method not requested. Skipping auth context provisioning");
            return null;
        }

        // Return cached context if already initiated
        if (authContextBean != null) {
            return authContextBean;
        }

        // Initiate OID4VP authentication
        String clientId = params.getFirst(OAuth2Constants.CLIENT_ID);
        AuthorizationContext authContext = startOpenID4VPAuthentication(clientId, false);
        AuthorizationContext authContextSameDevice = startOpenID4VPAuthentication(clientId, true);

        // Convert authorization request to QR code (cross-device)
        String authReqQrCode = turnToQrCodeImageData(authContext.getAuthorizationRequest());

        // Build URL for polling status (cross-device)
        String authStatusUrl = buildAuthStatusUrl(authContext.getTransactionId());

        // Gather context
        authContextBean = new AuthContextBean()
                .setAuthReqQrCode(authReqQrCode)
                .setAuthStatusUrl(authStatusUrl)
                .setAuthReqLink(authContextSameDevice.getAuthorizationRequest());

        return authContextBean;
    }

    private AuthorizationContext startOpenID4VPAuthentication(String clientId, boolean enableSameDeviceResponse) {
        // TODO: Generate and pass code challenge details for ownership binding and enhanced security in started subflow
        return oid4vp.startAuthentication(
                clientId, new OIDCAuthSession(authSessionId, getLoginActionUrl(), enableSameDeviceResponse), null);
    }

    private String buildAuthStatusUrl(String transactionId) {
        URI currentUri = session.getContext().getUri().getBaseUri();
        return UriBuilder.fromUri(currentUri)
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path(OID4VPUserAuthEndpoint.AUTH_STATUS_PATH)
                .build(realm.getName(), transactionId)
                .toString();
    }

    private String turnToQrCodeImageData(String data) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(
                    data,
                    BarcodeFormat.QR_CODE,
                    QR_CODE_IMAGE_SIZE,
                    QR_CODE_IMAGE_SIZE,
                    // Set margin to 0 to remove default padding
                    Map.of(EncodeHintType.MARGIN, 0));

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, QR_CODE_IMAGE_FORMAT, bos);

            byte[] pngBytes = bos.toByteArray();
            String base64 = Base64.getEncoder().encodeToString(pngBytes);

            return String.format("data:image/%s;base64,%s", QR_CODE_IMAGE_FORMAT, base64);
        } catch (WriterException | IOException e) {
            throw new RuntimeException("QR code creating failed", e);
        }
    }

    /**
     * Track session data of OIDC authentication
     */
    public record OIDCAuthSession(String authSessionId, String loginActionUrl, boolean enableSameDeviceResponse) {}

    /**
     * Parameters for OpenID4VP authentication
     */
    public static class AuthContextBean {

        private String authReqLink;
        private String authReqQrCode;
        private String authStatusUrl;

        public String getAuthReqLink() {
            return authReqLink;
        }

        public AuthContextBean setAuthReqLink(String authReqLink) {
            this.authReqLink = authReqLink;
            return this;
        }

        public String getAuthReqQrCode() {
            return authReqQrCode;
        }

        public AuthContextBean setAuthReqQrCode(String authReqQrCode) {
            this.authReqQrCode = authReqQrCode;
            return this;
        }

        public String getAuthStatusUrl() {
            return authStatusUrl;
        }

        public AuthContextBean setAuthStatusUrl(String authStatusUrl) {
            this.authStatusUrl = authStatusUrl;
            return this;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            AuthContextBean that = (AuthContextBean) o;
            return Objects.equals(getAuthReqLink(), that.getAuthReqLink())
                    && Objects.equals(getAuthReqQrCode(), that.getAuthReqQrCode())
                    && Objects.equals(getAuthStatusUrl(), that.getAuthStatusUrl());
        }

        @Override
        public int hashCode() {
            return Objects.hash(getAuthReqLink(), getAuthReqQrCode(), getAuthStatusUrl());
        }
    }
}
