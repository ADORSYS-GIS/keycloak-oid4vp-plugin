package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.io.ByteArrayInputStream;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
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

    private static final int MAX_CHAIN_LENGTH = 5;

    private PKIXVerificationUtil() {}

    public static X509Certificate[] validateBase64Chain(List<String> certs, TruststoreProvider truststoreProvider)
            throws VerificationException {
        return validateChain(parseX509Certificates(certs), truststoreProvider);
    }

    public static X509Certificate[] validateBase64Chain(
            List<String> certs, Collection<X509Certificate> rootCertificates) throws VerificationException {
        return validateChain(parseX509Certificates(certs), rootCertificates, List.of());
    }

    public static X509Certificate[] validateChain(List<X509Certificate> certs, TruststoreProvider truststoreProvider)
            throws VerificationException {
        List<X509Certificate> roots = truststoreProvider == null
                ? List.of()
                : truststoreProvider.getRootCertificates().values().stream()
                        .flatMap(List::stream)
                        .toList();
        List<X509Certificate> intermediates = truststoreProvider == null
                ? List.of()
                : truststoreProvider.getIntermediateCertificates().values().stream()
                        .flatMap(List::stream)
                        .toList();
        return validateChain(certs, roots, intermediates);
    }

    private static X509Certificate[] validateChain(
            List<X509Certificate> certs,
            Collection<X509Certificate> rootCertificates,
            Collection<X509Certificate> intermediateCertificates)
            throws VerificationException {
        try {
            if (certs == null || certs.isEmpty()) {
                throw new VerificationException("Certificate chain is empty");
            }

            if (certs.size() > MAX_CHAIN_LENGTH) {
                throw new VerificationException(
                        String.format("Certificate chain too long: %d (max %d)", certs.size(), MAX_CHAIN_LENGTH));
            }

            if (rootCertificates == null || rootCertificates.isEmpty()) {
                throw new VerificationException("No trusted root certificates available for validation");
            }

            // Build trust anchors from roots
            Set<TrustAnchor> trustAnchors = rootCertificates.stream()
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

            // Add intermediate certificates from the truststore as a CertStore so PKIX
            // can bridge chains where the issuer CA is stored as an intermediate.
            Collection<X509Certificate> intermediates =
                    intermediateCertificates == null ? List.of() : intermediateCertificates;
            if (!intermediates.isEmpty()) {
                params.addCertStore(
                        CertStore.getInstance("Collection", new CollectionCertStoreParameters(intermediates)));
            }

            // Validate the path. The CertPath should not include the trust anchor itself.
            List<X509Certificate> pathCerts = new ArrayList<>(certs);
            X509Certificate leafCert = pathCerts.getFirst();
            X509Certificate lastCert = pathCerts.getLast();

            boolean leafIsTrusted = trustAnchors.stream()
                    .anyMatch(anchor -> anchor.getTrustedCert().equals(leafCert));

            // If the leaf is directly trusted (e.g. self-signed trusted cert), we are done.
            if (leafIsTrusted) {
                leafCert.checkValidity(params.getDate());
                return certs.toArray(new X509Certificate[0]);
            }

            boolean rootInPath = trustAnchors.stream()
                    .anyMatch(anchor -> anchor.getTrustedCert().equals(lastCert));

            if (rootInPath && pathCerts.size() > 1) {
                pathCerts.removeLast();
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(pathCerts);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

            return certs.toArray(new X509Certificate[0]);

        } catch (VerificationException e) {
            throw e;
        } catch (Exception e) {
            throw new VerificationException("Certificate chain validation failed", e);
        }
    }

    private static List<X509Certificate> parseX509Certificates(List<String> base64Certs) throws VerificationException {
        if (base64Certs == null || base64Certs.isEmpty()) {
            throw new VerificationException("Certificate chain is empty");
        }

        try {
            List<X509Certificate> certs = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (String base64Cert : base64Certs) {
                byte[] bytes = Base64.getDecoder().decode(base64Cert);
                certs.add((X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes)));
            }
            return certs;
        } catch (CertificateException e) {
            throw new VerificationException("Failed to parse X.509 certificate", e);
        }
    }
}
