package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import javax.security.auth.x500.X500Principal;

/**
 * Provides the trust anchors (root and intermediate CA certificates) used to
 * PKIX-validate issuer certificate chains.
 *
 * <p>This is a lightweight, self-contained abstraction: implementations are plain
 * objects and are not tied to any Keycloak SPI lifecycle.
 */
public interface TrustAnchorProvider {

    Map<X500Principal, List<X509Certificate>> getRootCertificates();

    Map<X500Principal, List<X509Certificate>> getIntermediateCertificates();
}
