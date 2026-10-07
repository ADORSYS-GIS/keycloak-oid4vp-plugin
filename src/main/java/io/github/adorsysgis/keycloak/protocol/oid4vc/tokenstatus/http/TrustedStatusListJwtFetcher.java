package io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorAdapter;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.broker.provider.TrustMaterialResolver;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.utils.StringUtil;

/**
 * Fetches Status List JWTs and verifies their signatures against configured Keycloak trust-material
 * providers, or the global truststore when no providers are configured.
 *
 * <p>A configured provider selection is authoritative: provider resolution or validation failures
 * never fall back to the global truststore.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcher extends SimpleStatusListJwtFetcher {

    private static final String ISSUER_CLAIM = "iss";

    private final TrustMaterialResolver trustMaterialResolver;

    public TrustedStatusListJwtFetcher(KeycloakSession session) {
        this(session, new TrustMaterialResolver());
    }

    protected TrustedStatusListJwtFetcher(KeycloakSession session, TrustMaterialResolver trustMaterialResolver) {
        super(session);
        this.trustMaterialResolver = trustMaterialResolver;
    }

    @Override
    public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        return fetchStatusListJwt(uri, null);
    }

    @Override
    public String fetchStatusListJwt(String uri, String trustMaterialProviderAliases)
            throws ReferencedTokenValidationException {
        // Enforce HTTPS
        if (!uri.startsWith("https://")) {
            throw new ReferencedTokenValidationException("Status list JWT URI must use HTTPS: " + uri);
        }

        // Retrieve status list JWT
        String statusListJwt = super.fetchStatusListJwt(uri);
        JWSInput jws = parseStatusListJwt(statusListJwt);

        // Verify signature and certificate chain
        verifyStatusListJwt(jws, trustMaterialProviderAliases);

        return statusListJwt;
    }

    /**
     * Verifies the signature and certificate chain of the Status List JWT.
     */
    protected void verifyStatusListJwt(JWSInput jws, String trustMaterialProviderAliases)
            throws ReferencedTokenValidationException {
        PublicKey verificationKey = StringUtil.isBlank(trustMaterialProviderAliases)
                ? getLeafCertificateFromX5C(jws).getPublicKey()
                : resolveVerificationKey(jws, trustMaterialProviderAliases);
        SignatureVerifierContext verifier = getVerifierContext(jws, verificationKey);
        validateJwsSignature(jws, verifier);
    }

    private PublicKey resolveVerificationKey(JWSInput jws, String trustMaterialProviderAliases)
            throws ReferencedTokenValidationException {
        String algorithm = jws.getHeader().getRawAlgorithm();
        TrustMaterialRequest request = TrustMaterialRequest.builder()
                .kid(jws.getHeader().getKeyId())
                .algorithm(algorithm)
                .issuer(readIssuer(jws))
                .build();
        try {
            JWK trustedKey = trustMaterialResolver.validateX509Chain(
                    session,
                    trustMaterialProviderAliases,
                    request,
                    jws.getHeader().getX5c(),
                    algorithm);
            if (trustedKey == null) {
                throw new ReferencedTokenValidationException(
                        "No configured trust-material identity provider supplied X.509 trust");
            }
            PublicKey publicKey = JWKParser.create(trustedKey).toPublicKey();
            if (publicKey == null) {
                throw new ReferencedTokenValidationException(
                        "Configured trust-material identity provider returned an unsupported verification key");
            }
            return publicKey;
        } catch (ReferencedTokenValidationException e) {
            throw e;
        } catch (VerificationException e) {
            throw new ReferencedTokenValidationException(
                    "Status List JWT x5c validation through configured trust-material providers failed", e);
        } catch (RuntimeException e) {
            throw new ReferencedTokenValidationException(
                    "Could not resolve a Status List JWT verification key from configured trust-material providers", e);
        }
    }

    private String readIssuer(JWSInput jws) throws ReferencedTokenValidationException {
        try {
            // This claim is only a trust-material selector. It is not trusted until the JWS
            // signature has been verified with the key returned by the selected provider.
            JsonNode issuer = jws.readJsonContent(JsonNode.class).get(ISSUER_CLAIM);
            return issuer != null && issuer.isTextual() ? issuer.asText() : null;
        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException("Failed to parse Status List JWT claims", e);
        }
    }

    protected void validateJwsSignature(JWSInput jws, SignatureVerifierContext verifier)
            throws ReferencedTokenValidationException {
        try {
            byte[] signature = jws.getSignature();
            byte[] data = jws.getEncodedSignatureInput().getBytes(StandardCharsets.UTF_8);

            if (!verifier.verify(data, signature)) {
                throw new ReferencedTokenValidationException("Invalid JWS signature");
            }
        } catch (ReferencedTokenValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Signature verification failed: " + e.getMessage(), e);
        }
    }

    protected JWSInput parseStatusListJwt(String statusListJwt) throws ReferencedTokenValidationException {
        try {
            return new JWSInput(statusListJwt);
        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException("Failed to parse Status List JWT", e);
        }
    }

    protected X509Certificate getLeafCertificateFromX5C(JWSInput jws) throws ReferencedTokenValidationException {
        List<String> x5c = jws.getHeader().getX5c();
        if (x5c == null || x5c.isEmpty()) {
            throw new ReferencedTokenValidationException(
                    "Could not extract verifier from X5C certificate chain",
                    new VerificationException("Missing x5c header"));
        }

        X509Certificate[] chain = validateCertChain(x5c);
        X509Certificate leaf = chain[0];

        try {
            validateLeafCertificate(leaf);
        } catch (VerificationException e) {
            throw new ReferencedTokenValidationException("Leaf certificate validation failed", e);
        }

        return leaf;
    }

    protected SignatureVerifierContext getVerifierContext(JWSInput jws, PublicKey publicKey)
            throws ReferencedTokenValidationException {
        String alg = jws.getHeader().getRawAlgorithm();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        if (signatureProvider == null) {
            throw new ReferencedTokenValidationException("Unsupported algorithm: " + alg);
        }

        try {
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setPublicKey(publicKey);
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(algorithmToKeyType(alg));
            keyWrapper.setUse(KeyUse.SIG);
            return signatureProvider.verifier(keyWrapper);
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Failed to create signature verifier for " + alg, e);
        }
    }

    protected X509Certificate[] validateCertChain(List<String> x5c) throws ReferencedTokenValidationException {
        // Enforce trust in X5C chain
        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            throw new ReferencedTokenValidationException(
                    "No Keycloak global truststore configured; cannot validate certificate chain");
        }

        try {
            return PKIXVerificationUtil.validateBase64Chain(x5c, new TrustAnchorAdapter(truststoreProvider));
        } catch (VerificationException e) {
            throw new ReferencedTokenValidationException(e.getMessage(), e);
        }
    }

    public void validateLeafCertificate(X509Certificate leaf) throws VerificationException {
        if (leaf.getBasicConstraints() != -1) {
            throw new VerificationException("Leaf certificate must not be a CA");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && !keyUsage[0]) {
            throw new VerificationException("Leaf certificate missing Digital Signature KeyUsage");
        }
    }

    private static String algorithmToKeyType(String alg) throws ReferencedTokenValidationException {
        if (Algorithm.ES256.equals(alg) || Algorithm.ES384.equals(alg) || Algorithm.ES512.equals(alg)) {
            return KeyType.EC;
        }
        if (Algorithm.RS256.equals(alg)
                || Algorithm.RS384.equals(alg)
                || Algorithm.RS512.equals(alg)
                || Algorithm.PS256.equals(alg)
                || Algorithm.PS384.equals(alg)
                || Algorithm.PS512.equals(alg)) {
            return KeyType.RSA;
        }
        throw new ReferencedTokenValidationException("Unsupported signature algorithm: " + alg);
    }
}
