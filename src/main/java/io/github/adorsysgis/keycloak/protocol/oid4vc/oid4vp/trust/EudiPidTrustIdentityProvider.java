package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Stream;
import org.keycloak.broker.provider.TrustMaterialIdentityProvider;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.X509CertificateChainValidator;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.models.KeycloakSession;
import org.keycloak.utils.StringUtil;

/** Exposes certificates from a signed ETSI PID Provider LoTE as X.509 trust material. */
public class EudiPidTrustIdentityProvider implements TrustMaterialIdentityProvider<EudiPidTrustIdentityProviderConfig> {

    private final EudiPidTrustIdentityProviderConfig config;
    private final EudiPidTrustListProvider trustListProvider;

    public EudiPidTrustIdentityProvider(KeycloakSession session, EudiPidTrustIdentityProviderConfig config) {
        this(config, new EudiPidTrustListProvider(session));
    }

    EudiPidTrustIdentityProvider(
            EudiPidTrustIdentityProviderConfig config, EudiPidTrustListProvider trustListProvider) {
        this.config = config;
        this.trustListProvider = trustListProvider;
    }

    @Override
    public EudiPidTrustIdentityProviderConfig getConfig() {
        return config;
    }

    @Override
    public Stream<JWK> resolveKeys(TrustMaterialRequest request) {
        return Stream.empty();
    }

    @Override
    public JWK validateX509Chain(TrustMaterialRequest request, List<String> x5c, String algorithm)
            throws VerificationException {
        try {
            EudiPidTrustListProvider.TrustListSnapshot snapshot = trustListProvider.resolve(config.toTrustPolicy());
            List<X509Certificate> trustedCertificates = StringUtil.isBlank(config.getIssuer())
                    ? snapshot.trustedIssuerCertificates()
                    : snapshot.resolveIssuer(config.getIssuer()).trustedCertificates();

            List<X509Certificate> presentedChain = X509CertificateChainValidator.decodeCertificateChain(x5c);
            X509Certificate leaf = presentedChain.getFirst();
            if (trustedCertificates.contains(leaf)) {
                validatePublishedSignerCertificate(leaf);
                return X509CertificateChainValidator.toJwk(leaf, algorithm, presentedChain);
            }

            return X509CertificateChainValidator.validate(x5c, algorithm, trustedCertificates, List.of());
        } catch (EudiPidTrustException e) {
            throw new VerificationException("Could not resolve X.509 trust from the EUDI PID trust list", e);
        }
    }

    /**
     * A PID Provider list may publish the end-entity service certificate itself instead of a CA
     * root. In that case the certificate is an explicit pin, so no path can or needs to be built.
     */
    private static void validatePublishedSignerCertificate(X509Certificate certificate) throws VerificationException {
        try {
            certificate.checkValidity();
            if (certificate.getBasicConstraints() >= 0) {
                throw new VerificationException("A published signer certificate must be an end-entity certificate");
            }
            boolean[] keyUsage = certificate.getKeyUsage();
            if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
                throw new VerificationException("A published signer certificate must be valid for digital signatures");
            }
        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("The published signer certificate is not currently valid", e);
        }
    }

    @Override
    public void close() {}
}
