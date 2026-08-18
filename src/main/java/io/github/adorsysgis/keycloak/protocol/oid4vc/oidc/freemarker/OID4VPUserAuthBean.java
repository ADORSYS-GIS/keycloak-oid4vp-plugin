package io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.AuthorizationRequestService.CodeChallengeDetails;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.OID4VPLoginActionsService;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.OID4VPLoginActionsServiceFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.PresentationDuringIssuanceService;
import jakarta.ws.rs.core.UriBuilder;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.constants.ServiceUrlConstants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oidc.utils.PkceUtils;
import org.keycloak.sessions.AuthenticationSessionModel;

/**
 * View data for OpenID4VP login and authentication.
 */
public class OID4VPUserAuthBean {

    private static final Logger logger = Logger.getLogger(OID4VPUserAuthBean.class);

    public static final String PARAM_LOGIN_METHOD = "login_method";
    public static final String LOGIN_METHOD_OID4VP = "oid4vp";

    public static final String QR_CODE_IMAGE_FORMAT = "png";
    public static final int QR_CODE_IMAGE_SIZE = 300;

    private final KeycloakSession session;
    private final AuthenticationSessionModel authSession;
    private final URI actionUri;

    private final OID4VPUserAuthEndpoint oid4vp;
    private final PresentationDuringIssuanceService pdiService;
    private final boolean presentationDuringIssuanceRequired;

    private AuthContextBean authContextBean;

    public OID4VPUserAuthBean(
            KeycloakSession session,
            AuthenticationSessionModel authSession,
            URI actionUri,
            OID4VPUserAuthEndpoint oid4vp) {
        this.session = session;
        this.authSession = authSession;
        this.actionUri = actionUri;
        this.oid4vp = oid4vp;
        this.pdiService = new PresentationDuringIssuanceService(session, authSession);
        this.presentationDuringIssuanceRequired = pdiService.requiresNestedPresentationDuringIssuance();
    }

    /**
     * URLs to trigger UI views for every configured wallet authentication profile.
     */
    public List<LoginProfileBean> getLoginProfiles() {
        URI currentUri = session.getContext().getUri().getRequestUri();

        // Read client ID
        var params = session.getContext().getUri().getQueryParameters();
        String clientId = params.getFirst(OAuth2Constants.CLIENT_ID);

        // Validate client ID for OpenID4VP login
        try {
            oid4vp.checkClient(clientId);
        } catch (IllegalArgumentException e) {
            logger.debugf("Invalid client ID '%s' in OIDC URL. Not offering option for OpenID4VP login", clientId);
            return List.of();
        }

        try {
            Locale locale = session.getContext().resolveLocale(null);
            return oid4vp.getAuthenticationProfilesForClient(clientId).stream()
                    .filter(profile -> !profile.isSessionIdentityProfile())
                    .map(profile -> new LoginProfileBean()
                            .setId(profile.getId())
                            .setDisplayName(profile.getDisplayCta(locale))
                            .setLoginUrl(UriBuilder.fromUri(currentUri)
                                    .replaceQueryParam(PARAM_LOGIN_METHOD, LOGIN_METHOD_OID4VP)
                                    .replaceQueryParam(OID4VPUserAuthEndpoint.PROFILE_ID_PARAM, profile.getId())
                                    .build()
                                    .toString()))
                    .toList();
        } catch (IllegalArgumentException | IllegalStateException e) {
            logger.warnf(e, "Invalid OpenID4VP authentication profile configuration. Not offering wallet login");
            return List.of();
        }
    }

    /**
     * Drive view to display consent page for redirecting to the wallet
     * with a same-device authorization request.
     */
    public boolean isPresentationDuringIssuance() {
        return presentationDuringIssuanceRequired;
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
                .build(authSession.getRealm().getName())
                .toString();
    }

    /**
     * Initiate OID4VP authentication and pass authorization context to UI.
     */
    public AuthContextBean getAuthContext() {
        // Return cached context if already initiated
        if (authContextBean != null) {
            return authContextBean;
        }

        // Provision auth context for presentation during issuance
        if (isPresentationDuringIssuance()) {
            return getPdiAuthContext();
        }

        // Skip provisioning auth context if not login method OpenID4VP
        var params = session.getContext().getUri().getQueryParameters();
        if (!LOGIN_METHOD_OID4VP.equals(params.getFirst(PARAM_LOGIN_METHOD))) {
            logger.debugf("OpenID4VP login method not requested. Skipping auth context provisioning");
            return null;
        }

        // Initiate cross-device flow (cross-device QR flow drives status polling + /code redemption)
        String clientId = params.getFirst(OAuth2Constants.CLIENT_ID);
        String profileId = params.getFirst(OID4VPUserAuthEndpoint.PROFILE_ID_PARAM);
        OpenId4vpPkce crossDevicePkce = OpenId4vpPkce.generate();
        AuthorizationContext authContext = oid4vp.startAuthentication(
                clientId,
                profileId,
                new OIDCAuthSession(authSessionId(), getLoginActionUrl(), false),
                crossDevicePkce.challengeDetails(),
                null);

        // Initiate same-device flow
        AuthorizationContext authContextSameDevice = oid4vp.startAuthentication(
                clientId, profileId, new OIDCAuthSession(authSessionId(), getLoginActionUrl(), true), null, null);

        // Convert authorization request to QR code (cross-device)
        String authReqQrCode = turnToQrCodeImageData(authContext.getAuthorizationRequest());

        // Build URLs for polling status and PKCE-protected code redemption
        String authStatusUrl = buildAuthStatusUrl(authContext.getTransactionId());
        String authCodeRedemptionUrl = buildAuthCodeRedemptionUrl();

        // Gather context
        authContextBean = new AuthContextBean()
                .setAuthReqQrCode(authReqQrCode)
                .setAuthStatusUrl(authStatusUrl)
                .setAuthCodeRedemptionUrl(authCodeRedemptionUrl)
                .setTransactionId(authContext.getTransactionId())
                .setCodeVerifier(crossDevicePkce.codeVerifier())
                .setAuthReqLink(authContextSameDevice.getAuthorizationRequest());

        return authContextBean;
    }

    /**
     * Initiate same-device auth context for presentation during issuance
     */
    private AuthContextBean getPdiAuthContext() {
        var params = session.getContext().getUri().getQueryParameters();
        String clientId = params.getFirst(OAuth2Constants.CLIENT_ID);
        String profileId = pdiService.resolveEnforcedProfileId();
        if (profileId == null) {
            logger.error("Presentation during issuance requested without an enforced presentation profile");
            return new AuthContextBean().setError(true);
        }

        String subjectUserId = pdiService.resolveOfferSubjectUserId();
        AuthorizationContext authContext = oid4vp.startAuthentication(
                clientId,
                profileId,
                new OIDCAuthSession(authSessionId(), getLoginActionUrl(), true),
                null,
                subjectUserId);

        return new AuthContextBean().setAuthReqLink(authContext.getAuthorizationRequest());
    }

    private String authSessionId() {
        return Optional.ofNullable(authSession)
                .map(OID4VPUserAuthEndpointBase::getAuthSessionId)
                .orElse(null);
    }

    private String buildAuthCodeRedemptionUrl() {
        URI currentUri = session.getContext().getUri().getBaseUri();
        return UriBuilder.fromUri(currentUri)
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path(OID4VPUserAuthEndpoint.AUTH_CODE_PATH)
                .build(authSession.getRealm().getName())
                .toString();
    }

    private String buildAuthStatusUrl(String transactionId) {
        URI currentUri = session.getContext().getUri().getBaseUri();
        return UriBuilder.fromUri(currentUri)
                .path(ServiceUrlConstants.REALM_INFO_PATH)
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path(OID4VPUserAuthEndpoint.AUTH_STATUS_PATH)
                .build(authSession.getRealm().getName(), transactionId)
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
     * Track session data of OIDC authentication.
     *
     * @param authSessionId           the OIDC auth session id
     * @param loginActionUrl          the login action URL for resuming the OIDC flow
     * @param enableSameDeviceResponse whether to enable the same-device response flow
     */
    public record OIDCAuthSession(String authSessionId, String loginActionUrl, boolean enableSameDeviceResponse) {}

    public static class LoginProfileBean {

        private String id;
        private String displayName;
        private String loginUrl;

        public String getId() {
            return id;
        }

        public LoginProfileBean setId(String id) {
            this.id = id;
            return this;
        }

        public String getDisplayName() {
            return displayName;
        }

        public LoginProfileBean setDisplayName(String displayName) {
            this.displayName = displayName;
            return this;
        }

        public String getLoginUrl() {
            return loginUrl;
        }

        public LoginProfileBean setLoginUrl(String loginUrl) {
            this.loginUrl = loginUrl;
            return this;
        }
    }

    /**
     * Parameters for OpenID4VP authentication
     */
    public static class AuthContextBean {

        private String authReqLink;
        private String authReqQrCode;
        private String authStatusUrl;
        private String authCodeRedemptionUrl;
        private String transactionId;
        private String codeVerifier;
        private boolean error;

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

        public String getAuthCodeRedemptionUrl() {
            return authCodeRedemptionUrl;
        }

        public AuthContextBean setAuthCodeRedemptionUrl(String authCodeRedemptionUrl) {
            this.authCodeRedemptionUrl = authCodeRedemptionUrl;
            return this;
        }

        public String getTransactionId() {
            return transactionId;
        }

        public AuthContextBean setTransactionId(String transactionId) {
            this.transactionId = transactionId;
            return this;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public AuthContextBean setCodeVerifier(String codeVerifier) {
            this.codeVerifier = codeVerifier;
            return this;
        }

        public boolean getError() {
            return error;
        }

        public AuthContextBean setError(boolean error) {
            this.error = error;
            return this;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null || getClass() != o.getClass()) return false;
            AuthContextBean that = (AuthContextBean) o;
            return Objects.equals(getAuthReqLink(), that.getAuthReqLink())
                    && Objects.equals(getAuthReqQrCode(), that.getAuthReqQrCode())
                    && Objects.equals(getAuthStatusUrl(), that.getAuthStatusUrl())
                    && Objects.equals(getAuthCodeRedemptionUrl(), that.getAuthCodeRedemptionUrl())
                    && Objects.equals(getTransactionId(), that.getTransactionId())
                    && Objects.equals(getCodeVerifier(), that.getCodeVerifier())
                    && Objects.equals(getError(), that.getError());
        }

        @Override
        public int hashCode() {
            return Objects.hash(
                    getAuthReqLink(),
                    getAuthReqQrCode(),
                    getAuthStatusUrl(),
                    getAuthCodeRedemptionUrl(),
                    getTransactionId(),
                    getCodeVerifier(),
                    getError());
        }
    }

    private record OpenId4vpPkce(String codeVerifier, CodeChallengeDetails challengeDetails) {
        private static OpenId4vpPkce generate() {
            String codeVerifier = PkceUtils.generateCodeVerifier();
            String codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256);
            return new OpenId4vpPkce(
                    codeVerifier, new CodeChallengeDetails(codeChallenge, OAuth2Constants.PKCE_METHOD_S256));
        }
    }
}
