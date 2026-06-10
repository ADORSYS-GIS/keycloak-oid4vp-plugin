package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oidc.freemarker.OID4VPUserAuthBean.OIDCAuthSession;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils.EphemeralKey;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapabilities;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlQueryValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestUriMethod;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseType;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SpacephobicJwsBuilder;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.VerifierInfoSupport;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.jboss.logging.Logger;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwe.JWEUtils;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.SessionExpiration;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.utils.StringUtil;

/**
 * Dedicated service for creating OpenID4VP authorization requests for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationRequestService {

    private static final Logger logger = Logger.getLogger(AuthorizationRequestService.class);

    public static final String AUTH_REQ_JWT = "oauth-authz-req+jwt";
    public static final String X509_ATTR_CN = "CN";
    // The number of bytes to generate for secure random strings,
    // including request IDs, transaction IDs, and nonces (doubled).
    public static final int SECURE_RANDOM_ENTROPY = 20;

    // Note: "https://self-issued.me/v2" is a symbolic string and can be used
    // as an aud Claim value even when this specification is used standalone,
    // without SIOPv2.
    public static final String SYMBOLIC_AUD = "https://self-issued.me/v2";

    private final KeycloakSession session;
    private final DcqlCredentialCapabilities dcqlCapabilities;
    private final VerifierDiscoveryService discoveryService;

    private final String openID4VPRootUrl;
    private final int authSessionLifespanSecs;

    public AuthorizationRequestService(KeycloakSession session) {
        this(session, DcqlCredentialCapabilities.createDefault());
    }

    public AuthorizationRequestService(KeycloakSession session, DcqlCredentialCapabilities dcqlCapabilities) {
        this.session = session;
        this.dcqlCapabilities = dcqlCapabilities;
        this.discoveryService = new VerifierDiscoveryService(session, dcqlCapabilities);
        this.openID4VPRootUrl = OID4VPUserAuthEndpointBase.getOpenID4VPRootUrl(session);

        // Read the authentication session lifespan from the realm configuration
        RealmModel realm = session.getContext().getRealm();
        this.authSessionLifespanSecs = SessionExpiration.getAuthSessionLifespan(realm);
    }

    /**
     * Creates a fresh authorization request for user authentication.
     */
    public AuthorizationContext createAuthorizationRequest(
            VerifierConfig config,
            AuthenticationSessionModel authSession,
            OIDCAuthSession oidcAuthSession,
            CodeChallengeDetails codeChallengeParams) {
        logger.debug("Creating a fresh authorization request for user authentication...");

        // Generate random request and transaction IDs.
        // Different IDs are used to prevent unintended access to the status of this request.
        String requestId = generateSessionBoundId(authSession);
        String transactionId = generateSessionBoundId(authSession);

        // Generate response code to attach to context for same-device responses
        oidcAuthSession = Optional.ofNullable(oidcAuthSession).orElse(new OIDCAuthSession(null, null, false));
        String responseCode = oidcAuthSession.enableSameDeviceResponse() ? generateSessionBoundId(authSession) : null;

        // Generate ephemeral encryption keys if direct_post.jwt. Must be done before creating
        // the request object, so updated client metadata are picked up as intended.
        EphemeralKey encryptionKey = generateEncryptionKeyIfNeeded(config.getResponseMode());

        // Discover signing key
        KeyWrapper signingKey = discoverSigningKey(config);

        // Resolve and validate the certificate that will be advertised under x5c.
        X509Certificate certificate = resolveAccessCertificate(config, signingKey);

        // Resolve client ID and discover client metadata
        String clientId = discoveryService.getClientId(config.getClientIdentifierPrefix(), certificate);
        ClientMetadata clientMetadata = discoveryService.getClientMetadata(encryptionKey);

        // Build request object with DCQL query from the active format capability
        RequestObject requestObject = buildRequestObject(clientId, clientMetadata, config, requestId);

        // Sign request object initially, unless we know request_uri_method = post
        String requestObjectJwt = null;
        if (!RequestUriMethod.POST.equals(config.getRequestUriMethod())) {
            requestObjectJwt = signRequestObject(requestObject, signingKey, certificate);
        }

        // Build authorization request link
        String urlScheme = config.getAuthReqUrlScheme();
        String authorizationRequestLink =
                buildAuthorizationRequestLink(urlScheme, clientId, requestId, config.getRequestUriMethod());

        // Gather authorization context
        AuthorizationContext authorizationContext = new AuthorizationContext()
                .setStatus(AuthorizationContextStatus.PENDING)
                .setRequestId(requestId)
                .setTransactionId(transactionId)
                .setParentAuthSessionId(oidcAuthSession.authSessionId())
                .setLoginActionUrl(oidcAuthSession.loginActionUrl())
                .setRequestObject(requestObject)
                .setRequestObjectJwt(requestObjectJwt)
                .setAuthorizationRequest(authorizationRequestLink)
                .setRequestUriMethod(config.getRequestUriMethod())
                .setResponseCode(responseCode);

        // Attach code challenge details for ownership binding if present
        if (codeChallengeParams != null) {
            authorizationContext
                    .setCodeChallenge(codeChallengeParams.codeChallenge())
                    .setCodeChallengeMethod(codeChallengeParams.codeChallengeMethod());
        }

        // Attach ephemeral private key for decrypting direct_post.jwt responses.
        // The matching public key and kid are advertised in the signed request object's client_metadata.jwks.
        if (encryptionKey != null) {
            authorizationContext.setEphemeralKey(EphemeralKeyUtils.toBase64String(encryptionKey.privateKey()));
        }

        // Store authorization context in the authentication session
        AuthenticationSessionStore store = new AuthenticationSessionStore(authSession);
        store.storeAuthorizationContext(authorizationContext);

        // Pursue creation process
        return authorizationContext;
    }

    private X509Certificate resolveAccessCertificate(VerifierConfig config, KeyWrapper signingKey) {
        X509Certificate configuredCertificate = config.getAccessCertificate();
        if (configuredCertificate == null) {
            return getSelfSignedCertificate(signingKey);
        }

        ConfiguredAccessCertificateValidator.validate(configuredCertificate, signingKey);
        return configuredCertificate;
    }

    /**
     * Generates a session-bound ID, e.g., a request ID or transaction ID.
     */
    public static String generateSessionBoundId(AuthenticationSessionModel authSession) {
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
     * Discovers signing key.
     */
    private KeyWrapper discoverSigningKey(VerifierConfig config) {
        X509Certificate accessCertificate = config.getAccessCertificate();
        boolean requireSelfSignedCert = accessCertificate == null;
        return discoveryService.getSigningKey(requireSelfSignedCert);
    }

    /**
     * Generates ephemeral key for response encryption.
     */
    private EphemeralKey generateEncryptionKeyIfNeeded(ResponseMode responseMode) {
        if (!ResponseMode.DIRECT_POST_JWT.equals(responseMode)) {
            return null;
        }

        return EphemeralKeyUtils.generateEphemeralECDHKey();
    }

    /**
     * Returns a starter for building request objects.
     */
    private RequestObject buildRequestObject(
            String clientId, ClientMetadata clientMetadata, VerifierConfig config, String requestId) {
        String responseUri = KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                .path(OID4VPUserAuthEndpoint.RESPONSE_URI_PATH)
                .path(requestId)
                .build()
                .toString();

        // Generate nonce
        String nonce = Stream.generate(AuthorizationRequestService::generateRandomString)
                .limit(2)
                .collect(Collectors.joining("."));

        var dcqlCapability = dcqlCapabilities.resolve(config);
        DcqlQuery dcqlQuery = dcqlCapability.buildAuthorizationQuery(config);
        DcqlQueryValidator.validateQuery(dcqlQuery);

        // Single-credential SD-JWT login flow: transaction_data and verifier_info reference this id.
        // Multi-credential queries would need coordinated changes in response extraction and wiring.
        String dcqlCredentialId = dcqlQuery.getCredentials().getFirst().getId();

        List<String> transactionData = config.getTransactionDataRaw().isEmpty()
                ? null
                : TransactionDataSupport.prepareWireEntries(config.getTransactionDataRaw(), dcqlCredentialId);

        var verifierInfo = VerifierInfoSupport.build(
                config.getRegistrationCertificate(), config.getVerifierInfoConfig(), dcqlCredentialId);

        // Aggregate properties
        RequestObject requestObject = new RequestObject()
                .setIssuer(clientId)
                .setResponseMode(config.getResponseMode())
                .setResponseUri(responseUri)
                .setResponseType(ResponseType.VP_TOKEN)
                .setClientId(clientId)
                .setNonce(nonce)
                .setState(requestId)
                .setAudience(SYMBOLIC_AUD)
                .setClientMetadata(clientMetadata)
                .setVerifierInfo(verifierInfo)
                .setTransactionData(transactionData);

        requestObject.setDcqlQuery(dcqlQuery);

        return requestObject;
    }

    private String buildAuthorizationRequestLink(
            String urlScheme, String clientId, String requestId, RequestUriMethod requestUriMethod) {
        var requestUri = KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                .path(OID4VPUserAuthEndpoint.REQUEST_JWT_PATH)
                .path(requestId)
                .build()
                .toString();

        String requestUriMethodQuery = RequestUriMethod.POST.equals(requestUriMethod) ? "&request_uri_method=post" : "";
        return String.format(
                "%sauthorize?client_id=%s&request_uri=%s%s",
                urlScheme,
                URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8),
                requestUriMethodQuery);
    }

    private String signRequestObject(RequestObject requestObject, VerifierConfig config) {
        KeyWrapper signingKey = discoverSigningKey(config);
        X509Certificate certificate = resolveAccessCertificate(config, signingKey);
        return signRequestObject(requestObject, signingKey, certificate);
    }

    /**
     * Finalizes authorization request given wallet-provided data.
     */
    public AuthorizationContext finalizeAuthorizationRequest(
            VerifierConfig config,
            AuthenticationSessionModel authSession,
            AuthorizationContext authContext,
            String walletNonce,
            JsonNode walletMetadata) {

        boolean contextChanged = false;
        if (walletMetadata != null) {
            authContext.setWalletMetadata(walletMetadata);
            contextChanged = true;
        }

        RequestObject requestObject = authContext.getRequestObject();
        boolean mustSign = false;

        if (StringUtil.isNotBlank(walletNonce)) {
            requestObject.setWalletNonce(walletNonce);
            authContext.setRequestObject(requestObject);
            mustSign = true;
        }

        String requestObjectJwt = authContext.getRequestObjectJwt();
        if (requestObjectJwt == null || mustSign) {
            requestObjectJwt = signRequestObject(requestObject, config);
            authContext.setRequestObjectJwt(requestObjectJwt);
            contextChanged = true;
        }

        if (contextChanged) {
            new AuthenticationSessionStore(authSession).storeAuthorizationContext(authContext);
        }

        return authContext;
    }

    private String signRequestObject(RequestObject requestObject, KeyWrapper signingKey, X509Certificate certificate) {
        logger.debug("Signing request object");
        Long expiration = Instant.now().plusSeconds(authSessionLifespanSecs).getEpochSecond();
        requestObject.issuedNow().exp(expiration).id(UUID.randomUUID().toString());

        // Derive signer context
        String algorithm = signingKey.getAlgorithmOrDefault();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, algorithm);
        SignatureSignerContext signer = signatureProvider.signer(signingKey);

        return new SpacephobicJwsBuilder()
                .type(AUTH_REQ_JWT)
                .x5c(List.of(certificate))
                .jsonContent(requestObject)
                .sign(signer);
    }

    private X509Certificate getSelfSignedCertificate(KeyWrapper signingKey) {
        X509Certificate cert = signingKey.getCertificate();
        if (cert == null) {
            throw new IllegalStateException("Signing key has no certificate");
        }

        String clientId = discoveryService.getDnsNameClientId();
        PublicKey publicKey = (PublicKey) signingKey.getPublicKey();
        PrivateKey privateKey = (PrivateKey) signingKey.getPrivateKey();

        // Generate a new self-signed certificate with SAN matching client ID
        try {
            return ExtendedCertificateUtils.generateV3Certificate(
                    privateKey, cert, publicKey, getIssuerCN(cert), List.of(clientId));
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
    /**
     * Record to hold PKCE parameters for passing around concisely.
     */
    public record CodeChallengeDetails(String codeChallenge, String codeChallengeMethod) {}
}
