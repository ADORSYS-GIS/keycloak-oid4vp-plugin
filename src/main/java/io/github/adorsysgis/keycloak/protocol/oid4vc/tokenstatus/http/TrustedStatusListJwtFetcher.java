package io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http;

import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;

/**
 * Status list JWT data fetcher with trust enforcement.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcher extends SimpleStatusListJwtFetcher {

    private static final Logger logger = Logger.getLogger(TrustedStatusListJwtFetcher.class);
    private static final int MAX_CERT_CHAIN_LENGTH = 5;

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

        SignatureVerifierContext verifier = getVerifierFromX5C(jws);
        validateJwsSignature(jws, verifier);

        return statusListJwt;
    }

    protected String _fetchStatusListJwt(String uri) throws ReferencedTokenValidationException {
        return super.fetchStatusListJwt(uri);
    }

    private JWSInput parseStatusListJwt(String statusListJwt) throws ReferencedTokenValidationException {
        try {
            return new JWSInput(statusListJwt);
        } catch (JWSInputException e) {
            throw new ReferencedTokenValidationException("Retrieved status list is not a valid JWT", e);
        }
    }

    private SignatureVerifierContext getVerifierFromX5C(JWSInput jws) throws ReferencedTokenValidationException {

        try {
            JWSHeader header = jws.getHeader();
            List<String> x5cList = header.getX5c();

            if (x5cList == null || x5cList.isEmpty()) {
                throw new VerificationException("Missing or empty x5c header in JWS");
            }

            if (x5cList.size() > MAX_CERT_CHAIN_LENGTH) {
                throw new VerificationException("Certificate chain too long: " + x5cList.size());
            }

            X509Certificate[] certChain = parseCertificates(x5cList);

            // Validate leaf constraints
            X509Certificate leaf = certChain[0];
            validateLeafCertificate(leaf);

            // Validate PKIX chain against truststore
            validateCertChain(certChain);

            // Ensure algorithm matches key type
            validateAlgorithmCompatibility(leaf, header.getAlgorithm().name());

            return toSignatureVerifier(leaf, header.getAlgorithm().name());
        } catch (ReferencedTokenValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Could not extract verifier from X5C certificate chain", e);
        }
    }

    private X509Certificate[] parseCertificates(List<String> x5cList) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] certChain = new X509Certificate[x5cList.size()];

        for (int i = 0; i < x5cList.size(); i++) {
            byte[] decoded = Base64.getDecoder().decode(x5cList.get(i).replaceAll("\\s", ""));
            certChain[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
        }

        return certChain;
    }

    public void validateLeafCertificate(X509Certificate leaf) throws VerificationException {
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && !keyUsage[0]) {
            throw new VerificationException("Leaf certificate missing Digital Signature KeyUsage");
        }

        if (leaf.getBasicConstraints() != -1) {
            throw new VerificationException("Leaf certificate must not be a CA");
        }
    }

    protected void validateCertChain(X509Certificate[] certChain) throws ReferencedTokenValidationException {

        try {
            Date validationDate = new Date(Time.currentTimeMillis());

            // Check validity dates
            for (X509Certificate cert : certChain) {
                cert.checkValidity(validationDate);
            }

            TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
            if (truststoreProvider == null) {
                throw new ReferencedTokenValidationException("TruststoreProvider not available");
            }

            if (truststoreProvider.getTruststore() == null) {
                logger.warn(
                        "Keycloak global truststore not configured. Certificate validation may rely on internal system defaults.");
                throw new ReferencedTokenValidationException("Truststore not configured");
            }

            logger.debug("Using Keycloak global truststore for certificate chain validation");

            Set<X509Certificate> trustedRoots = truststoreProvider.getRootCertificates().values().stream()
                    .flatMap(List::stream)
                    .collect(Collectors.toSet());

            Set<X509Certificate> trustedIntermediates =
                    truststoreProvider.getIntermediateCertificates().values().stream()
                            .flatMap(List::stream)
                            .collect(Collectors.toSet());

            if (trustedRoots.isEmpty()) {
                throw new ReferencedTokenValidationException("No trusted root certificates available for validation");
            }

            buildAndValidatePKIX(certChain, trustedRoots, trustedIntermediates, validationDate);

        } catch (ReferencedTokenValidationException e) {
            logger.errorf("Token validation failed: %s", e.getMessage());
            throw e;
        } catch (Exception e) {
            logger.errorf(e, "Certificate chain validation failed: %s", e.getMessage());
            throw new ReferencedTokenValidationException("Certificate chain validation failed", e);
        }
    }

    private void buildAndValidatePKIX(
            X509Certificate[] certChain,
            Set<X509Certificate> trustedRoots,
            Set<X509Certificate> trustedIntermediates,
            Date validationDate)
            throws GeneralSecurityException {

        X509CertSelector selector = new X509CertSelector();
        selector.setCertificate(certChain[0]);

        Set<TrustAnchor> trustAnchors =
                trustedRoots.stream().map(cert -> new TrustAnchor(cert, null)).collect(Collectors.toSet());

        PKIXBuilderParameters params = new PKIXBuilderParameters(trustAnchors, selector);
        params.setDate(validationDate);

        // SECURITY NOTE:
        // Certificate Revocation Checking (Certificate Revocation List / Online Certificate Status Protocol) is
        // currently disabled.
        // This means revoked certificates may still be accepted.
        params.setRevocationEnabled(false);

        // Treat all provided certs as possible intermediates (no ordering trust)
        Set<X509Certificate> allIntermediates = new HashSet<>(trustedIntermediates);
        allIntermediates.addAll(Arrays.asList(certChain));

        CertStore certStore =
                CryptoIntegration.getProvider().getCertStore(new CollectionCertStoreParameters(allIntermediates));

        params.addCertStore(certStore);

        CertPathBuilder builder = CryptoIntegration.getProvider().getCertPathBuilder();
        builder.build(params);
        logger.debug("Certificate chain validation successful");
    }

    private void validateAlgorithmCompatibility(X509Certificate cert, String alg) throws VerificationException {

        PublicKey key = cert.getPublicKey();

        boolean compatible =
                switch (alg) {
                    case Algorithm.RS256,
                            Algorithm.RS384,
                            Algorithm.RS512,
                            Algorithm.PS256,
                            Algorithm.PS384,
                            Algorithm.PS512 -> key instanceof RSAPublicKey;

                    case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> key instanceof ECPublicKey;

                    default -> false;
                };

        if (!compatible) {
            throw new VerificationException("Algorithm does not match certificate public key type");
        }
    }

    private SignatureVerifierContext toSignatureVerifier(X509Certificate cert, String alg)
            throws VerificationException, ReferencedTokenValidationException {

        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, alg);
        if (signatureProvider == null) {
            throw new ReferencedTokenValidationException("Unsupported signature algorithm: " + alg);
        }

        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setPublicKey(cert.getPublicKey());
        keyWrapper.setType(algorithmToKeyType(alg));
        keyWrapper.setAlgorithm(alg);

        return signatureProvider.verifier(keyWrapper);
    }

    protected String algorithmToKeyType(String alg) throws ReferencedTokenValidationException {
        return switch (alg) {
            case Algorithm.RS256, Algorithm.RS384, Algorithm.RS512, Algorithm.PS256, Algorithm.PS384, Algorithm.PS512 ->
                KeyType.RSA;

            case Algorithm.ES256, Algorithm.ES384, Algorithm.ES512 -> KeyType.EC;

            default -> throw new ReferencedTokenValidationException("Unsupported signature algorithm");
        };
    }

    private void validateJwsSignature(JWSInput jws, SignatureVerifierContext verifier)
            throws ReferencedTokenValidationException {

        try {
            if (!verifier.verify(jws.getEncodedSignatureInput().getBytes(), jws.getSignature())) {
                throw new ReferencedTokenValidationException("Invalid JWS signature");
            }
        } catch (ReferencedTokenValidationException e) {
            throw e;
        } catch (Exception e) {
            throw new ReferencedTokenValidationException("Error during JWS signature verification", e);
        }
    }
}
