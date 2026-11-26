package io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub;

import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.ExistingCertificate;
import io.github.adorsysgis.keycloak.protocol.oid4vc.eudihub.model.hub.AccessCertificate;
import jakarta.ws.rs.WebApplicationException;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;

/** Finds an EUDI Hub certificate that matches the current OpenID4VP signing key. */
final class ExistingAccessCertificateFinder {

    private static final Logger logger = Logger.getLogger(ExistingAccessCertificateFinder.class);

    private final CertificateLister certificateLister;
    private final CertificateDownloader certificateDownloader;

    ExistingAccessCertificateFinder(CertificateLister certificateLister, CertificateDownloader certificateDownloader) {
        this.certificateLister = certificateLister;
        this.certificateDownloader = certificateDownloader;
    }

    /**
     * Looks up a matching certificate on a best-effort basis
     */
    Optional<ExistingCertificate> find(String token, String organizationId, String environment, KeyWrapper signingKey) {
        if (signingKey == null || signingKey.getPublicKey() == null) {
            return Optional.empty();
        }

        List<AccessCertificate> certificates;
        try {
            certificates = certificateLister.list(token, organizationId, environment);
        } catch (WebApplicationException e) {
            logger.warnf(e, "Could not list the access certificates of EUDI Hub organization %s", organizationId);
            return Optional.empty();
        }

        byte[] signingPublicKey = signingKey.getPublicKey().getEncoded();
        for (AccessCertificate candidate : certificates) {
            byte[] der;
            try {
                der = certificateDownloader.download(token, organizationId, candidate);
            } catch (WebApplicationException e) {
                logger.warnf(
                        e,
                        "Could not download EUDI Hub access certificate %s while looking for the signing key's certificate",
                        candidate.id());
                continue;
            }
            if (holdsPublicKey(der, signingPublicKey, candidate.id())) {
                return Optional.of(new ExistingCertificate(candidate, der));
            }
        }
        return Optional.empty();
    }

    private static boolean holdsPublicKey(byte[] der, byte[] publicKey, String certificateId) {
        try {
            X509Certificate certificate = (X509Certificate)
                    CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            return Arrays.equals(certificate.getPublicKey().getEncoded(), publicKey);
        } catch (CertificateException e) {
            logger.warnf(
                    e, "Could not parse EUDI Hub access certificate %s while checking its public key", certificateId);
            return false;
        }
    }

    @FunctionalInterface
    interface CertificateLister {
        List<AccessCertificate> list(String token, String organizationId, String environment);
    }

    @FunctionalInterface
    interface CertificateDownloader {
        byte[] download(String token, String organizationId, AccessCertificate certificate);
    }
}
