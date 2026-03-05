package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.HashException;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.def.BCCertificateUtilsProvider;

public class ExtendedCertificateUtils extends CertificateUtils {

    private static final Logger logger = Logger.getLogger(ExtendedCertificateUtils.class);

    private static final int DEFAULT_MAX_CACHE_SIZE = 1000;

    private static Cache<CacheKey, X509Certificate> certificateCache = createCache(DEFAULT_MAX_CACHE_SIZE);

    private static Cache<CacheKey, X509Certificate> createCache(int maxSize) {
        return Caffeine.newBuilder()
                .maximumSize(maxSize)
                .expireAfterWrite(ExtendedBCCertificateUtilsProvider.DEFAULT_CERT_VALIDITY_MS, TimeUnit.MILLISECONDS)
                .ticker(() -> Time.currentTimeMillis() * 1_000_000L)
                .build();
    }

    /**
     * Initializes the certificate cache with configuration from Keycloak.
     * @param config The configuration scope.
     */
    public static synchronized void init(Config.Scope config) {
        int maxSize = config.getInt("cache-max-size", DEFAULT_MAX_CACHE_SIZE);
        logger.debugf("Initializing ExtendedCertificateUtils with max cache size: %d", maxSize);
        certificateCache = createCache(maxSize);
    }

    static Cache<CacheKey, X509Certificate> getCache() {
        return certificateCache;
    }

    private record CacheKey(String caCertHash, String subPubKeyHash, String subject, List<String> sans) {}

    public static ExtendedCertificateUtilsProvider getExtendedCertificateUtilsProvider() {
        // FIXME: Overriding DefaultCryptoProvider from an extension does not work as expected.
        //  This swapping logic constitutes a reliable workaround. On the other hand, it also
        //  helps isolating the effect of ExtendedCertificateUtilsProvider to the logic in this
        //  extension only, avoiding unintended side effects on other Keycloak components.

        CryptoProvider cryptoProvider = CryptoIntegration.getProvider();
        var certUtilsProviderClass = Optional.ofNullable(cryptoProvider)
                .map(CryptoProvider::getCertificateUtils)
                .map(Object::getClass)
                .orElseThrow(() -> new IllegalStateException("CryptoProvider is not initialized properly"));

        // TODO: Add support for other CryptoProviders (Elytron / FIPS)

        if (certUtilsProviderClass == BCCertificateUtilsProvider.class) {
            return ExtendedBCCertificateUtilsProvider.getInstance();
        } else {
            String message = "ExtendedCertificateUtilsProvider is not supported by the configured CryptoProvider: "
                    + certUtilsProviderClass.getName();
            throw new UnsupportedOperationException(message);
        }
    }

    /**
     * Generates or retrieves a cached X509v3 certificate.
     * <p>
     * This method uses a Caffeine-backed LRU cache to avoid expensive BouncyCastle generation
     * operations on every request. It performs the following steps:
     * <ol>
     *     <li>Creates a cache key based on the CA certificate, subject public key, subject name, and SANs.</li>
     *     <li>Checks the cache for an existing certificate.</li>
     *     <li>If found, verifies the certificate's validity (not expired).</li>
     *     <li>If expired or missing, triggers generation via the {@link ExtendedCertificateUtilsProvider}.</li>
     * </ol>
     *
     * @param caPrivateKey   The private key of the CA.
     * @param caCert         The CA certificate.
     * @param subPublicKey   The public key for the new certificate.
     * @param subject        The subject name (CN).
     * @param subjectAltNames List of Subject Alternative Names (DNS names).
     * @return A valid X509Certificate.
     * @throws HashException if cache key generation fails.
     */
    public static X509Certificate generateV3Certificate(
            PrivateKey caPrivateKey,
            X509Certificate caCert,
            PublicKey subPublicKey,
            String subject,
            List<String> subjectAltNames) {
        CacheKey key = createCacheKey(caCert, subPublicKey, subject, subjectAltNames);

        // 1. Peek at the cache
        X509Certificate cached = certificateCache.getIfPresent(key);
        if (cached != null) {
            logger.debugf("Cache hit for key: %s", key);
            return cached;
        }

        // 2. Load the certificate atomically
        return certificateCache.get(key, k -> {
            logger.debugf("Generating new certificate for key: %s", k);
            return getExtendedCertificateUtilsProvider()
                    .generateV3Certificate(caPrivateKey, caCert, subPublicKey, subject, subjectAltNames);
        });
    }

    private static CacheKey createCacheKey(
            X509Certificate caCert, PublicKey subPublicKey, String subject, List<String> sans) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance(JavaAlgorithm.SHA256);
            String caCertHash = Base64.getEncoder().encodeToString(sha256.digest(caCert.getEncoded()));
            String subPubKeyHash = Base64.getEncoder().encodeToString(sha256.digest(subPublicKey.getEncoded()));
            return new CacheKey(caCertHash, subPubKeyHash, subject, sans);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new HashException("Failed to create cache key for certificate", e);
        }
    }
}
