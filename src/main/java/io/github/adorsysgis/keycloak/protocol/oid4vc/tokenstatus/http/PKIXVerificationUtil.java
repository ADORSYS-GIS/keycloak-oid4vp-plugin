package io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Time;
import org.keycloak.truststore.TruststoreProvider;

public class PKIXVerificationUtil {

    public static X509Certificate[] validateChain(List<String> x5c, TruststoreProvider truststoreProvider)
            throws VerificationException {
        try {
            if (x5c == null || x5c.isEmpty()) {
                throw new VerificationException("Certificate chain is empty");
            }

            if (x5c.size() > 5) {
                throw new VerificationException("Certificate chain too long: " + x5c.size());
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certs = new ArrayList<>();
            for (String base64Cert : x5c) {
                byte[] bytes = Base64.getDecoder().decode(base64Cert);
                certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes)));
            }

            if (truststoreProvider == null
                    || truststoreProvider.getRootCertificates().isEmpty()) {
                throw new VerificationException("No trusted root certificates available for validation");
            }

            // Build trust anchors from roots
            Set<TrustAnchor> trustAnchors = truststoreProvider.getRootCertificates().values().stream()
                    .flatMap(List::stream)
                    .map(cert -> new TrustAnchor(cert, null))
                    .collect(Collectors.toSet());

            if (trustAnchors.isEmpty()) {
                throw new VerificationException("No trusted root certificates available for validation");
            }

            PKIXParameters params = new PKIXParameters(trustAnchors);
            // TODO: Revocation checking is currently disabled to avoid blocking network I/O during validation.
            // For production-grade revocation, set to true and configure a PKIXRevocationChecker or
            // provide a CRL cert store via params.addCertStore().
            params.setRevocationEnabled(false);
            // Sync with Keycloak offset time for testing (and production time consistency)
            params.setDate(new Date(Time.currentTimeMillis()));

            // Add intermediate certificates from the truststore and the presented chain
            // as a CertStore so PKIX can bridge chains where the issuer CA is stored as
            // an intermediate (not repeated in the JWT x5c array).
            Collection<X509Certificate> allIntermediates = new ArrayList<>(certs);
            truststoreProvider.getIntermediateCertificates().values().stream()
                    .flatMap(List::stream)
                    .forEach(allIntermediates::add);
            params.addCertStore(
                    CertStore.getInstance("Collection", new CollectionCertStoreParameters(allIntermediates)));

            // Validate the path. The CertPath should not include the trust anchor itself.
            List<X509Certificate> pathCerts = new ArrayList<>(certs);
            X509Certificate lastCert = pathCerts.get(pathCerts.size() - 1);
            boolean rootInPath = trustAnchors.stream()
                    .anyMatch(anchor -> anchor.getTrustedCert().equals(lastCert));

            if (rootInPath && pathCerts.size() > 1) {
                pathCerts.remove(pathCerts.size() - 1);
            }

            CertPath certPath = cf.generateCertPath(pathCerts);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

            return certs.toArray(new X509Certificate[0]);

        } catch (VerificationException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new VerificationException("Certificate chain validation failed: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new VerificationException("Error during certificate chain validation: " + e.getMessage(), e);
        }
    }
}
