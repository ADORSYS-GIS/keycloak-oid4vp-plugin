package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.HashException;
import org.mockito.ArgumentMatchers;
import org.mockito.stubbing.Answer;

class ExtendedCertificateUtilsTest {

    private static KeyPair subKeyPair;
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    @BeforeAll
    static void setup() throws Exception {
        CryptoIntegration.init(ExtendedCertificateUtilsTest.class.getClassLoader());
        subKeyPair = TestCryptoUtils.generateRSAKeyPair(2048);
        caKeyPair = TestCryptoUtils.generateRSAKeyPair(2048);
        caCert = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);
    }

    @BeforeEach
    void initCache() {
        // Explicitly re-initialize the cache before every test to ensure isolation
        ExtendedCertificateUtils.init(createDefaultConfig());
        Time.setOffset(0);
    }

    private Config.Scope createDefaultConfig() {
        Config.Scope mockConfig = mock(Config.Scope.class);
        // Ensure that getInt returns the default value passed as the second argument
        Answer<Integer> defaultAnswer = invocation -> invocation.getArgument(1);
        when(mockConfig.getInt(ArgumentMatchers.anyString(), ArgumentMatchers.anyInt()))
                .thenAnswer(defaultAnswer);
        return mockConfig;
    }

    @AfterAll
    static void tearDown() {
        Time.setOffset(0);
    }

    @Test
    void testGenerateV3Certificate_caching() {
        String subject = "cache-test";
        List<String> sans = List.of("cache.com");

        X509Certificate cert1 = generateCert(subject, sans);
        X509Certificate cert2 = generateCert(subject, sans);

        assertNotNull(cert1);
        assertNotNull(cert2);
        assertSame(cert1, cert2, "Certificate should be cached and reused instance");
    }

    @Test
    void testGenerateV3Certificate_cacheMissOnDifferentParams() {
        X509Certificate cert1 = generateCert("s1", List.of("a.com"));
        X509Certificate cert2 = generateCert("s2", List.of("a.com"));
        X509Certificate cert3 = generateCert("s1", List.of("b.com"));

        assertNotSame(cert1, cert2, "Different subjects should result in different certificates");
        assertNotSame(cert1, cert3, "Different SANs should result in different certificates");
    }

    @Test
    void testGenerateV3Certificate_cacheMissOnCaRotation() throws Exception {
        KeyPair caKeyPair2 = TestCryptoUtils.generateRSAKeyPair(2048);
        X509Certificate caCert2 = TestCryptoUtils.createSelfSignedCaCert(caKeyPair2);

        String subject = "rotation-test";

        X509Certificate cert1 = generateCert(subject);
        X509Certificate cert2 = ExtendedCertificateUtils.generateV3Certificate(
                caKeyPair2.getPrivate(), caCert2, subKeyPair.getPublic(), subject, List.of());

        assertNotSame(cert1, cert2, "Different CA certificates should result in different verifier certificates");
    }

    @Test
    void testGenerateV3Certificate_concurrency() {
        String subject = "concurrency-test";
        int threadCount = 10;
        List<CompletableFuture<X509Certificate>> futures = Stream.generate(
                        () -> CompletableFuture.supplyAsync(() -> generateCert(subject)))
                .limit(threadCount)
                .toList();

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        X509Certificate firstCert = futures.getFirst().join();
        futures.stream()
                .skip(1)
                .forEach(f -> assertSame(firstCert, f.join(), "All threads should receive the same cached instance"));
    }

    @Test
    void testCreateCacheKey_HashException() throws Exception {
        X509Certificate brokenCert = mock(X509Certificate.class);
        when(brokenCert.getEncoded()).thenThrow(new CertificateEncodingException("broken"));

        assertThrows(
                HashException.class,
                () -> ExtendedCertificateUtils.generateV3Certificate(
                        caKeyPair.getPrivate(), brokenCert, subKeyPair.getPublic(), "subject", List.of()));
    }

    @Test
    void testGenerateV3Certificate_cacheEviction() {
        Config.Scope mockConfig = mock(Config.Scope.class);
        when(mockConfig.getInt("cache-max-size", 1000)).thenReturn(10);

        ExtendedCertificateUtils.init(mockConfig);

        try {
            X509Certificate firstCert = generateCert("evict-subject-0");
            IntStream.rangeClosed(1, 15).forEach(i -> generateCert("evict-subject-" + i));

            ExtendedCertificateUtils.getCache().cleanUp();
            X509Certificate refilledFirstCert = generateCert("evict-subject-0");

            assertNotSame(firstCert, refilledFirstCert, "Entry should have been evicted from the size-limited cache");
        } finally {
            // Restore default configuration
            ExtendedCertificateUtils.init(mock(Config.Scope.class));
        }
    }

    @Test
    void testGenerateV3Certificate_cacheExpiration() {
        // Use default configuration (1h expiration)
        X509Certificate firstCert = generateCert("expire-subject");

        // Advance time by 2 hours using Time.setOffset
        Time.setOffset(2 * 3600);

        ExtendedCertificateUtils.getCache().cleanUp();
        X509Certificate refilledCert = generateCert("expire-subject");

        assertNotSame(firstCert, refilledCert, "Entry should have expired from the cache");
    }

    private X509Certificate generateCert(String subject) {
        return generateCert(subject, List.of());
    }

    private X509Certificate generateCert(String subject, List<String> sans) {
        return ExtendedCertificateUtils.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, sans);
    }
}
