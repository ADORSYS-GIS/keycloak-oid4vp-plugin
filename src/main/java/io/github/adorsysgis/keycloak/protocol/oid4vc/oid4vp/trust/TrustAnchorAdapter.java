package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import org.keycloak.truststore.TruststoreProvider;

/**
 * Adapts Keycloak's {@link TruststoreProvider} to our lightweight
 * {@link TrustAnchorProvider} so that PKIX validation only depends on the two
 * methods we actually need (root and intermediate trust-anchors).
 */
public final class TrustAnchorAdapter implements TrustAnchorProvider {

    private final TruststoreProvider delegate;

    public TrustAnchorAdapter(TruststoreProvider delegate) {
        this.delegate = delegate;
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
        return delegate.getRootCertificates();
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
        return delegate.getIntermediateCertificates();
    }
}
