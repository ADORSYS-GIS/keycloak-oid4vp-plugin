package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.truststore.TruststoreProvider;

/**
 * {@link TruststoreProvider} backed by a fixed set of trust-anchor certificates.
 *
 * <p>Anchors are exposed as root certificates (grouped by subject principal) so PKIX
 * validation can chain any presented issuer certificate to one of them.
 */
public class StaticTruststoreProvider implements TruststoreProvider {

    private final List<X509Certificate> anchors;

    public StaticTruststoreProvider(Collection<X509Certificate> anchors) {
        this.anchors = List.copyOf(anchors);
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
        return anchors.stream().collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal));
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
        return Map.of();
    }

    @Override
    public HostnameVerificationPolicy getPolicy() {
        return null;
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        return null;
    }

    @Override
    public KeyStore getTruststore() {
        return null;
    }

    @Override
    public void close() {}
}
