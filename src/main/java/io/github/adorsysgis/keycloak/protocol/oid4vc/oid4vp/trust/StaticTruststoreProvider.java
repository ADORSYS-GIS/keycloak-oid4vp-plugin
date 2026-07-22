package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;

/**
 * {@link TrustAnchorProvider} backed by a fixed set of trust-anchor certificates.
 *
 * <p>Anchors are exposed as root certificates (grouped by subject principal) so PKIX
 * validation can chain any presented issuer certificate to one of them.
 */
public class StaticTruststoreProvider implements TrustAnchorProvider {

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
}
