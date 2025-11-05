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

package org.keycloak.protocol.oid4vc.oid4vp.service;

import org.jboss.logging.Logger;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwe.JWEUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.SessionExpiration;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import org.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import org.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import org.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import org.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import org.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import org.keycloak.protocol.oid4vc.oid4vp.model.ResponseType;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import org.keycloak.protocol.oid4vc.oid4vp.utils.SpacephobicJwsBuilder;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Dedicated service for creating OpenID4VP authorization requests for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationRequestService {

    private static final Logger logger = Logger.getLogger(AuthorizationRequestService.class);

    public final static String AUTH_REQ_JWT = "oauth-authz-req+jwt";
    public final static String X509_ATTR_CN = "CN";

    // The number of bytes to generate for secure random strings,
    // including request IDs, transaction IDs, and nonces (doubled).
    public static final int SECURE_RANDOM_ENTROPY = 20;

    // Note: "https://self-issued.me/v2" is a symbolic string and can be used
    // as an aud Claim value even when this specification is used standalone,
    // without SIOPv2.
    public static final String SYMBOLIC_AUD = "https://self-issued.me/v2";

    private final ClientMetadata clientMetadata;
    private final String openID4VPRootUrl;
    private final KeyWrapper signingKey;
    private final SignatureSignerContext signer;
    private final int authSessionLifespanSecs;

    public AuthorizationRequestService(KeycloakSession session) {
        // Discover client metadata and signing key
        VerifierDiscoveryService verifierDiscoveryService = new VerifierDiscoveryService(session);
        this.clientMetadata = verifierDiscoveryService.getClientMetadata();
        this.openID4VPRootUrl = verifierDiscoveryService.getOpenID4VPRootUrl();
        this.signingKey = verifierDiscoveryService.getSigningKey();

        // Derive signer context
        Objects.requireNonNull(signingKey);
        String algorithm = signingKey.getAlgorithmOrDefault();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
        this.signer = signatureProvider.signer(signingKey);

        // Read the authentication session lifespan from the realm configuration
        RealmModel realm = session.getContext().getRealm();
        this.authSessionLifespanSecs = SessionExpiration.getAuthSessionLifespan(realm);
    }

    /**
     * Creates a fresh authorization request for user authentication.
     */
    public AuthorizationContext createAuthorizationRequest(
            AuthenticationSessionModel authSession,
            SdJwtAuthRequirements authReqs
    ) {
        logger.debug("Creating a fresh authorization request for user authentication...");

        // Generate random request and transaction IDs.
        // Different IDs are used to prevent unintended access to the status of this request.
        String requestId = generateRequestOrTransactionId(authSession);
        String transactionId = generateRequestOrTransactionId(authSession);

        // Load presentation definition for SD-JWT authentication
        var presentationDefinition = authReqs.getDIFPresentationDefinition();

        // Build request object
        RequestObject requestObject = bootstrapRequestObject()
                .setState(requestId)
                .setPresentationDefinition(presentationDefinition);

        // Sign request object
        String requestObjectJwt = signRequestObject(requestObject);

        // Build authorization request link
        String authorizationRequestLink = buildAuthorizationRequestLink(requestId);

        // Gather authorization context
        AuthorizationContext authorizationContext = new AuthorizationContext()
                .setStatus(AuthorizationContextStatus.PENDING)
                .setRequestId(requestId)
                .setTransactionId(transactionId)
                .setRequestObject(requestObject)
                .setRequestObjectJwt(requestObjectJwt)
                .setAuthorizationRequest(authorizationRequestLink);

        // Store authorization context in the authentication session
        AuthenticationSessionStore store = new AuthenticationSessionStore(authSession);
        store.storeAuthorizationContext(authorizationContext);

        // Pursue creation process
        return authorizationContext;
    }

    /**
     * Generates a request or transaction ID.
     */
    private static String generateRequestOrTransactionId(AuthenticationSessionModel authSession) {
        return OID4VPUserAuthEndpointBase.getAuthSessionId(authSession)
                + OID4VPUserAuthEndpointBase.AUTH_SESSION_EOL_MARKER
                + generateRandomString();
    }

    /**
     * Generates a cryptographically secure random string.
     */
    private static String generateRandomString() {
        // Generate a cryptographically secure random byte array
        byte[] randomBytes = JWEUtils.generateSecret(SECURE_RANDOM_ENTROPY);

        // Convert the random number to a Base64 string
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Returns a starter for building request objects.
     */
    private RequestObject bootstrapRequestObject() {
        String clientId = clientMetadata.getClientId();
        String responseUri = openID4VPRootUrl + OID4VPUserAuthEndpoint.RESPONSE_URI_PATH;

        String nonce = Stream.generate(AuthorizationRequestService::generateRandomString)
                .limit(2)
                .collect(Collectors.joining("."));

        return new RequestObject()
                .setIssuer(clientId)
                .setResponseMode(ResponseMode.DIRECT_POST)
                .setResponseUri(responseUri)
                .setResponseType(ResponseType.VP_TOKEN)
                .setClientId(clientId)
                .setClientIdScheme(ClientIdScheme.X509_SAN_DNS)
                .setNonce(nonce)
                .setAudience(SYMBOLIC_AUD)
                .setClientMetadata(clientMetadata);
    }

    private String buildAuthorizationRequestLink(String requestId) {
        var clientId = clientMetadata.getClientId();
        var requestUri = openID4VPRootUrl + "%s/%s".formatted(
                OID4VPUserAuthEndpoint.REQUEST_JWT_PATH,
                requestId
        );

        return String.format("openid4vp://authorize?client_id=%s&request_uri=%s",
                URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
    }

    private String signRequestObject(RequestObject requestObject) {
        logger.debugf("Signing request object (%s)", requestObject.getState());
        Long expiration = Instant.now()
                .plusSeconds(authSessionLifespanSecs)
                .getEpochSecond();
        requestObject.issuedNow().exp(expiration);

        return new SpacephobicJwsBuilder()
                .type(AUTH_REQ_JWT)
                .x5c(List.of(getSelfSignedCertificate()))
                .jsonContent(requestObject)
                .sign(signer);
    }

    private X509Certificate getSelfSignedCertificate() {
        X509Certificate cert = signingKey.getCertificate();
        if (cert == null) {
            throw new IllegalStateException("Signing key has no certificate");
        }

        String clientId = clientMetadata.getClientId();
        KeyPair keyPair = new KeyPair(
                (PublicKey) signingKey.getPublicKey(),
                (PrivateKey) signingKey.getPrivateKey()
        );

        // Generate a new self-signed certificate with SAN matching client ID
        try {
            return CertificateUtils.generateV3Certificate(
                    keyPair,
                    keyPair.getPrivate(),
                    cert,
                    getIssuerCN(cert),
                    List.of(clientId)
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to regenerate certificate with SAN", e);
        }
    }

    private static String getIssuerCN(X509Certificate cert) {
        try {
            String dn = cert.getIssuerX500Principal().getName();
            LdapName ldapDN = new LdapName(dn);
            for (Rdn rdn : ldapDN.getRdns()) {
                if (rdn.getType().equalsIgnoreCase(X509_ATTR_CN)) {
                    return rdn.getValue().toString();
                }
            }
            return null;
        } catch (Exception e) {
            throw new RuntimeException("Failed to extract issuer CN from certificate", e);
        }
    }
}
