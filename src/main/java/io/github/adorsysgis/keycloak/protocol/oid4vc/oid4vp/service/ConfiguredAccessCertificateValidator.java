package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.jboss.logging.Logger;
import org.keycloak.crypto.KeyWrapper;

/**
 * Validates configured access certificates against the active signing key.
 *
 * <p>Successful validations are cached until the certificate expires so request creation
 * does not repeat the same checks on every invocation.
 *
 * @author <a href="mailto:Bertrand.Ogen@adorsys.com">Bertrand Ogen</a>
 */
final class ConfiguredAccessCertificateValidator {

    private static final Logger logger = Logger.getLogger(ConfiguredAccessCertificateValidator.class);

    private static final ConcurrentMap<ValidationCacheKey, Instant> validationCache = new ConcurrentHashMap<>();

    private ConfiguredAccessCertificateValidator() {}

    static void validate(X509Certificate configuredCertificate, KeyWrapper signingKey) {
        if (configuredCertificate == null) {
            return;
        }

        Instant now = Instant.now();
        ValidationCacheKey cacheKey = ValidationCacheKey.from(configuredCertificate, signingKey);
        validationCache.compute(cacheKey, (unused, validUntil) -> {
            if (validUntil != null && now.isBefore(validUntil)) {
                return validUntil;
            }

            validateCertificate(configuredCertificate, signingKey);
            Instant cacheUntil = configuredCertificate.getNotAfter().toInstant();
            logger.debugf(
                    "Validated configured access certificate against active signing key%s until %s",
                    formatKeyId(signingKey), cacheUntil);
            return cacheUntil;
        });
    }

    static void clearCache() {
        validationCache.clear();
    }

    static int cacheSize() {
        return validationCache.size();
    }

    private static void validateCertificate(X509Certificate configuredCertificate, KeyWrapper signingKey) {
        try {
            configuredCertificate.checkValidity();
        } catch (CertificateExpiredException e) {
            throw new IllegalStateException("Configured access certificate has expired", e);
        } catch (CertificateNotYetValidException e) {
            throw new IllegalStateException("Configured access certificate is not yet valid", e);
        }

        PublicKey signingPublicKey = getSigningPublicKey(signingKey);
        PublicKey certificatePublicKey = configuredCertificate.getPublicKey();
        if (!Arrays.equals(certificatePublicKey.getEncoded(), signingPublicKey.getEncoded())) {
            throw new IllegalStateException(
                    "Configured access certificate does not match the active signing key" + formatKeyId(signingKey));
        }
    }

    private static PublicKey getSigningPublicKey(KeyWrapper signingKey) {
        return (PublicKey) Objects.requireNonNull(signingKey.getPublicKey(), "Active signing key has no public key");
    }

    private static String formatKeyId(KeyWrapper signingKey) {
        return signingKey.getKid() == null ? "" : " '" + signingKey.getKid() + "'";
    }

    private static String fingerprint(byte[] encoded) {
        return HexFormat.of().formatHex(encoded);
    }

    private record ValidationCacheKey(String certificateFingerprint, String signingKeyFingerprint) {

        static ValidationCacheKey from(X509Certificate certificate, KeyWrapper signingKey) {
            try {
                return new ValidationCacheKey(
                        fingerprint(certificate.getEncoded()),
                        fingerprint(getSigningPublicKey(signingKey).getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Failed to encode configured access certificate", e);
            }
        }
    }
}
