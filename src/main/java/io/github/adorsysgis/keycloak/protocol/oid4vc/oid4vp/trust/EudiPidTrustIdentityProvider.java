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
    private final EudiCertificateChainValidator chainValidator = new EudiCertificateChainValidator();

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

            X509Certificate[] validatedChain = chainValidator.validatePublishedOrChained(x5c, trustedCertificates);
            return X509CertificateChainValidator.toJwk(validatedChain[0], algorithm, List.of(validatedChain));
        } catch (EudiPidTrustException e) {
            throw new VerificationException("Could not resolve X.509 trust from the EUDI PID trust list", e);
        }
    }

    @Override
    public void close() {}
}
