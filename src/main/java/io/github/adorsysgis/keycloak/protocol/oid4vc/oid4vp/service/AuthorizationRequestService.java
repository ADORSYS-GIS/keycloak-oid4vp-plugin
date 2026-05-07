package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils.EphemeralKey;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedCertificateUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpoint;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.OID4VPUserAuthEndpointBase;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.VerifierConfig;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientIdScheme;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.QueryLanguage;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseMode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseType;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.VerifierInfo;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContextStatus;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SpacephobicJwsBuilder;
import java.net.URI;
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

/**
 * Dedicated service for creating OpenID4VP authorization requests for user authentication.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class AuthorizationRequestService {

    private static final Logger logger = Logger.getLogger(AuthorizationRequestService.class);

    public static final String AUTH_REQ_JWT = "oauth-authz-req+jwt";
    public static final String X509_ATTR_CN = "CN";
    public static final String REGISTRATION_CERT_FORMAT = "registration_cert";

    // The number of bytes to generate for secure random strings,
    // including request IDs, transaction IDs, and nonces (doubled).
    public static final int SECURE_RANDOM_ENTROPY = 20;

    // Note: "https://self-issued.me/v2" is a symbolic string and can be used
    // as an aud Claim value even when this specification is used standalone,
    // without SIOPv2.
    public static final String SYMBOLIC_AUD = "https://self-issued.me/v2";

    private final KeycloakSession session;
    private final SdJwtCredentialConstrainer constrainer;
    private final VerifierDiscoveryService discoveryService;

    private final String openID4VPRootUrl;
    private final int authSessionLifespanSecs;

    public AuthorizationRequestService(KeycloakSession session) {
        this.session = session;
        this.constrainer = new SdJwtCredentialConstrainer();

        // Initialize discovery service
        this.discoveryService = new VerifierDiscoveryService(session);
        this.openID4VPRootUrl = discoveryService.getOpenID4VPRootUrl();

        // Read the authentication session lifespan from the realm configuration
        RealmModel realm = session.getContext().getRealm();
        this.authSessionLifespanSecs = SessionExpiration.getAuthSessionLifespan(realm);
    }

    /**
     * Creates a fresh authorization request for user authentication.
     */
    public AuthorizationContext createAuthorizationRequest(
            AuthenticationSessionModel authSession,
            String parentAuthSessionId,
            VerifierConfig config,
            CodeChallengeDetails codeChallengeParams) {
        logger.debug("Creating a fresh authorization request for user authentication...");

        // Generate random request and transaction IDs.
        // Different IDs are used to prevent unintended access to the status of this request.
        String requestId = generateRequestOrTransactionId(authSession);
        String transactionId = generateRequestOrTransactionId(authSession);

        // Generate ephemeral encryption keys if direct_post.jwt. Must be done before creating
        // the request object, so updated client metadata are picked up as intended.
        EphemeralKey encryptionKey = generateEncryptionKeyIfNeeded(config.getResponseMode());

        // Discover signing key
        KeyWrapper signingKey = discoverSigningKey(config);

        // Resolve and validate the certificate that will be advertised under x5c.
        X509Certificate certificate = resolveAccessCertificate(config, signingKey);

        // Resolve client ID and discover client metadata
        String clientId = discoveryService.getClientId(config.getClientIdScheme(), certificate);
        ClientMetadata clientMetadata = discoveryService.getClientMetadata(encryptionKey);

        // Load query map for SD-JWT authentication
        SdJwtAuthRequirements authReqs = config.getAuthRequirements();
        var queryMap = authReqs.getSdJwtQueryMap();

        // Build request object
        RequestObject requestObject = buildRequestObject(clientId, clientMetadata, config, queryMap, requestId);

        // Sign request object
        String requestObjectJwt = signRequestObject(requestObject, signingKey, certificate);

        // Build authorization request link
        String urlScheme = config.getAuthReqUrlScheme();
        String authorizationRequestLink = buildAuthorizationRequestLink(urlScheme, clientId, requestId);

        // Gather authorization context
        AuthorizationContext authorizationContext = new AuthorizationContext()
                .setStatus(AuthorizationContextStatus.PENDING)
                .setRequestId(requestId)
                .setTransactionId(transactionId)
                .setParentAuthSessionId(parentAuthSessionId)
                .setCodeChallenge(codeChallengeParams.codeChallenge())
                .setCodeChallengeMethod(codeChallengeParams.codeChallengeMethod())
                .setRequestObject(requestObject)
                .setRequestObjectJwt(requestObjectJwt)
                .setAuthorizationRequest(authorizationRequestLink);

        // Attach ephemeral key if generated
        if (encryptionKey != null) {
            String privKey = EphemeralKeyUtils.toBase64String(encryptionKey.privateKey());
            authorizationContext.setEphemeralKey(privKey);
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
            String clientId,
            ClientMetadata clientMetadata,
            VerifierConfig config,
            SdJwtCredentialConstrainer.QueryMap queryMap,
            String requestId) {
        String responseUri = KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                .path(OID4VPUserAuthEndpoint.RESPONSE_URI_PATH)
                .path(requestId)
                .build()
                .toString();
        validateResponseUri(responseUri, clientId, config.getClientIdScheme());

        // Generate nonce
        String nonce = Stream.generate(AuthorizationRequestService::generateRandomString)
                .limit(2)
                .collect(Collectors.joining("."));

        // If registration certificate configured, expose it under verifier info.
        // See https://bmi.usercontent.opencode.de/eudi-wallet/developer-guide/rp/onboarding/Example_BDB/
        String registrationCertificate = config.getRegistrationCertificate();
        List<VerifierInfo> verifierInfo = Optional.ofNullable(registrationCertificate)
                .map(rc -> new VerifierInfo().setData(rc).setFormat(REGISTRATION_CERT_FORMAT))
                .map(List::of)
                .orElse(null);

        // Aggregate properties
        RequestObject requestObject = new RequestObject()
                .setIssuer(clientId)
                .setResponseMode(config.getResponseMode())
                .setResponseUri(responseUri)
                .setResponseType(ResponseType.VP_TOKEN)
                .setClientId(clientId)
                .setClientIdScheme(config.getClientIdScheme())
                .setNonce(nonce)
                .setState(requestId)
                .setAudience(SYMBOLIC_AUD)
                .setClientMetadata(clientMetadata)
                .setVerifierInfo(verifierInfo);

        // Append presentation request
        QueryLanguage ql = config.getQueryLanguage();
        if (ql.equals(QueryLanguage.ALL) || ql.equals(QueryLanguage.DIF_PRESENTATION_EXCHANGE)) {
            // Kept for backward compatibility with Draft 20 wallets
            requestObject.setPresentationDefinition(constrainer.generatePresentationDefinition(queryMap));
        }
        if (ql.equals(QueryLanguage.ALL) || ql.equals(QueryLanguage.DCQL_QUERY)) {
            requestObject.setDcqlQuery(constrainer.generateDcqlQuery(queryMap));
        }

        return requestObject;
    }

    private static void validateResponseUri(String responseUri, String clientId, ClientIdScheme clientIdScheme) {
        URI uri;
        try {
            uri = URI.create(responseUri);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid response_uri", e);
        }

        if (uri.getHost() == null || uri.getHost().isBlank()) {
            throw new IllegalArgumentException("response_uri must include a host");
        }
        boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());
        boolean isLoopbackHttp = "http".equalsIgnoreCase(uri.getScheme()) && isLoopbackHost(uri.getHost());
        if (!isHttps && !isLoopbackHttp) {
            throw new IllegalArgumentException("response_uri must use https (or loopback http for local deployments)");
        }

        // Final 1.0: response_uri must satisfy prefix-specific constraints similarly to redirect_uri.
        switch (clientIdScheme) {
            case X509_SAN_DNS -> {
                String expectedDns = clientId.substring(clientId.indexOf(':') + 1);
                if (!expectedDns.equalsIgnoreCase(uri.getHost())) {
                    throw new IllegalArgumentException("response_uri host must match x509_san_dns client_id");
                }
            }
            case X509_HASH -> {
                // For x509_hash, verifier identity is bound through the x5c leaf-certificate hash,
                // so no additional host-to-client_id binding is defined here.
            }
            default ->
                throw new IllegalArgumentException(
                        "Unsupported client_id scheme for response_uri validation: " + clientIdScheme.getValue());
        }
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
    }

    private String buildAuthorizationRequestLink(String urlScheme, String clientId, String requestId) {
        var requestUri = KeycloakUriBuilder.fromUri(openID4VPRootUrl)
                .path(OID4VPUserAuthEndpoint.REQUEST_JWT_PATH)
                .path(requestId)
                .build()
                .toString();

        return String.format(
                "%sauthorize?client_id=%s&request_uri=%s",
                urlScheme,
                URLEncoder.encode(clientId, StandardCharsets.UTF_8),
                URLEncoder.encode(requestUri, StandardCharsets.UTF_8));
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
