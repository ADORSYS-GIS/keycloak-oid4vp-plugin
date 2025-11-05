/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.forms.login.freemarker.model;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointFactory;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.services.Urls;
import org.keycloak.services.resources.LoginActionsService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

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
    private final URI baseUri;

    private final OID4VPUserAuthEndpoint oid4VPUserAuthEndpoint;
    private AuthContextBean authContextBean;

    public OID4VPUserAuthBean(KeycloakSession session, RealmModel realm, URI baseUri) {
        this.session = session;
        this.realm = realm;
        this.baseUri = baseUri;

        ClientConnection connection = session.getContext().getConnection();
        EventBuilder event = new EventBuilder(realm, session, connection);
        this.oid4VPUserAuthEndpoint = new OID4VPUserAuthEndpoint(session, event);
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
            oid4VPUserAuthEndpoint.checkClient(clientId);
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
        return Urls.loginActionsBase(baseUri)
                .path(LoginActionsService.class, "oid4vpAuthLogin")
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
        AuthorizationContext authContext = oid4VPUserAuthEndpoint.startAuthentication(clientId);

        // Convert authorization request to QR code
        String authReqQrCode = turnToQrCodeImageData(authContext.getAuthorizationRequest());

        // Build URL for polling status
        String authStatusUrl = buildAuthStatusUrl(authContext.getTransactionId());

        // Collect and return context
        authContextBean = new AuthContextBean()
                .setAuthReqQrCode(authReqQrCode)
                .setAuthStatusUrl(authStatusUrl);
        return authContextBean;
    }

    private String buildAuthStatusUrl(String transactionId) {
        URI currentUri = session.getContext().getUri().getBaseUri();
        return UriBuilder.fromUri(currentUri)
                .path("/realms/{realm}")
                .path(OID4VPUserAuthEndpointFactory.PROVIDER_ID)
                .path(OID4VPUserAuthEndpoint.AUTH_STATUS_PATH)
                .build(realm.getName(), transactionId)
                .toString();
    }

    private String turnToQrCodeImageData(String data) {
        try {
            QRCodeWriter qrCodeWriter = new QRCodeWriter();
            BitMatrix bitMatrix = qrCodeWriter.encode(
                    data, BarcodeFormat.QR_CODE,
                    QR_CODE_IMAGE_SIZE, QR_CODE_IMAGE_SIZE,
                    // Set margin to 0 to remove default padding
                    Map.of(EncodeHintType.MARGIN, 0)
            );

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
     * Parameters for OpenID4VP authentication
     */
    public static class AuthContextBean {

        private String authReqQrCode;
        private String authStatusUrl;

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
            return Objects.equals(authReqQrCode, that.authReqQrCode) && Objects.equals(authStatusUrl, that.authStatusUrl);
        }

        @Override
        public int hashCode() {
            return Objects.hash(authReqQrCode, authStatusUrl);
        }
    }
}
