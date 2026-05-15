package io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http;

import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

/**
 * Enhanced fetcher that enforces trust through Keycloak's global truststore.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcher extends SimpleStatusListJwtFetcher {

    private static final Logger logger = Logger.getLogger(TrustedStatusListJwtFetcher.class);

    public TrustedStatusListJwtFetcher(KeycloakSession session) {
        super(session);
    }

    @Override
    public String fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        if (!uri.startsWith("https://")) {
            throw new ReferencedTokenValidationException("Status list JWT URI must use HTTPS: " + uri);
        }

        String statusListJwt = _fetchStatusListJwt(uri);
        JWSInput jws = parseStatusListJwt(statusListJwt);

        verifyStatusListJwt(jws, uri);

        return statusListJwt;
    }

    /**
     * Verifies the signature and certificate chain of the Status List JWT.
     */
    protected void verifyStatusListJwt(JWSInput jws, String uri) throws ReferencedTokenValidationException {
        X509Certificate leaf = getLeafCertificateFromX5C(jws);
        SignatureVerifierContext verifier = getVerifierContext(jws, leaf);
        validateJwsSignature(jws, verifier);
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

    protected SignatureVerifierContext getVerifierContext(JWSInput jws, X509Certificate certificate)
            throws ReferencedTokenValidationException {
        String alg = jws.getHeader().getRawAlgorithm();
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        if (signatureProvider == null) {
            throw new ReferencedTokenValidationException("Unsupported algorithm: " + alg);
        }

        try {
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setPublicKey(certificate.getPublicKey());
            keyWrapper.setAlgorithm(alg);
            keyWrapper.setType(algorithmToKeyType(alg));
            keyWrapper.setUse(KeyUse.SIG);
            return signatureProvider.verifier(keyWrapper);
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Failed to create signature verifier for " + alg, e);
        }
    }

    protected X509Certificate[] validateCertChain(List<String> x5c) throws ReferencedTokenValidationException {
        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        if (truststoreProvider == null || truststoreProvider.getTruststore() == null) {
            logger.warn("No Keycloak global truststore configured. Certificate chain validation will fail.");
        }

        try {
            return PKIXVerificationUtil.validateChain(x5c, truststoreProvider);
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
