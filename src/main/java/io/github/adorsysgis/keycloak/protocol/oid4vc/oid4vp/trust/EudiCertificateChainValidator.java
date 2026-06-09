package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.common.util.Time;

class EudiCertificateChainValidator {

    private static final int MAX_CHAIN_LENGTH = 5;

    X509Certificate[] validate(List<String> x5c, Collection<X509Certificate> trustedAnchors)
            throws EudiPidTrustException {
        try {
            if (x5c == null || x5c.isEmpty()) {
                throw new EudiPidTrustException("Credential issuer x5c chain is missing");
            }
            if (x5c.size() > MAX_CHAIN_LENGTH) {
                throw new EudiPidTrustException("Credential issuer x5c chain is too long");
            }
            if (trustedAnchors == null || trustedAnchors.isEmpty()) {
                throw new EudiPidTrustException("No EUDI PID trust anchors available");
            }

            List<X509Certificate> chain = new ArrayList<>();
            for (String cert : x5c) {
                chain.add(CertificateUtil.parseCertificate(cert));
            }

            Set<TrustAnchor> anchors = trustedAnchors.stream()
                    .map(cert -> new TrustAnchor(cert, null))
                    .collect(Collectors.toSet());
            PKIXParameters params = new PKIXParameters(anchors);
            // Credential revocation is enforced through Token Status List in this plugin.
            // CA/certificate revocation sources are not present in the German sandbox LoTE artifacts.
            params.setRevocationEnabled(false);
            params.setDate(new Date(Time.currentTimeMillis()));

            List<X509Certificate> pathCerts = new ArrayList<>(chain);
            X509Certificate leaf = pathCerts.get(0);
            leaf.checkValidity(params.getDate());
            validateLeafCertificate(leaf);

            boolean leafIsAnchor =
                    anchors.stream().anyMatch(anchor -> anchor.getTrustedCert().equals(leaf));
            if (leafIsAnchor) {
                return chain.toArray(new X509Certificate[0]);
            }

            X509Certificate last = pathCerts.get(pathCerts.size() - 1);
            boolean pathContainsAnchor =
                    anchors.stream().anyMatch(anchor -> anchor.getTrustedCert().equals(last));
            if (pathContainsAnchor && pathCerts.size() > 1) {
                pathCerts.remove(pathCerts.size() - 1);
            }

            List<X509Certificate> intermediates = new ArrayList<>(pathCerts);
            intermediates.remove(leaf);
            if (!intermediates.isEmpty()) {
                params.addCertStore(
                        CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediates)));
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(pathCerts);
            CertPathValidator.getInstance("PKIX").validate(certPath, params);
            return chain.toArray(new X509Certificate[0]);
        } catch (EudiPidTrustException e) {
            throw e;
        } catch (Exception e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        }
    }

    private void validateLeafCertificate(X509Certificate leaf) throws EudiPidTrustException {
        if (leaf.getBasicConstraints() != -1) {
            throw new EudiPidTrustException("Credential issuer leaf certificate must not be a CA");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && !keyUsage[0]) {
            throw new EudiPidTrustException("Credential issuer leaf certificate missing digitalSignature usage");
        }
    }
}
