package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.Config;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.HashException;
import org.keycloak.crypto.KeyType;

@org.junit.jupiter.api.TestMethodOrder(org.junit.jupiter.api.MethodOrderer.OrderAnnotation.class)
class ExtendedCertificateUtilsTest {

    private static KeyPair subKeyPair;
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    @BeforeAll
    static void setup() throws Exception {
        CryptoIntegration.init(ExtendedCertificateUtilsTest.class.getClassLoader());
        // Set a small offset to ensure notBefore (based on Time) is strictly in the past for checkValidity()
        Time.setOffset(10);

        subKeyPair = generateRSAKeyPair(2048);
        caKeyPair = generateRSAKeyPair(2048);
        caCert = createSelfSignedCaCert(caKeyPair);
    }

    @org.junit.jupiter.api.AfterAll
    static void tearDown() {
        Time.setOffset(0);
    }

    @Test
    @org.junit.jupiter.api.Order(1)
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
    @org.junit.jupiter.api.Order(2)
    void testGenerateV3Certificate_cacheMissOnDifferentParams() {
        X509Certificate cert1 = generateCert("s1", List.of("a.com"));
        X509Certificate cert2 = generateCert("s2", List.of("a.com"));
        X509Certificate cert3 = generateCert("s1", List.of("b.com"));

        assertNotSame(cert1, cert2, "Different subjects should result in different certificates");
        assertNotSame(cert1, cert3, "Different SANs should result in different certificates");
    }

    @Test
    @org.junit.jupiter.api.Order(3)
    void testGenerateV3Certificate_cacheMissOnCaRotation() throws Exception {
        KeyPair caKeyPair2 = generateRSAKeyPair(2048);
        X509Certificate caCert2 = createSelfSignedCaCert(caKeyPair2);

        String subject = "rotation-test";

        X509Certificate cert1 = generateCert(subject);
        X509Certificate cert2 = ExtendedCertificateUtils.generateV3Certificate(
                caKeyPair2.getPrivate(), caCert2, subKeyPair.getPublic(), subject, List.of());

        assertNotSame(cert1, cert2, "Different CA certificates should result in different verifier certificates");
    }

    @Test
    @org.junit.jupiter.api.Order(4)
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
    @org.junit.jupiter.api.Order(5)
    void testCreateCacheKey_HashException() throws Exception {
        X509Certificate brokenCert = mock(X509Certificate.class);
        when(brokenCert.getEncoded()).thenThrow(new CertificateEncodingException("broken"));

        assertThrows(
                HashException.class,
                () -> ExtendedCertificateUtils.generateV3Certificate(
                        caKeyPair.getPrivate(), brokenCert, subKeyPair.getPublic(), "subject", List.of()));
    }

    @Test
    @org.junit.jupiter.api.Order(6)
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

    private X509Certificate generateCert(String subject) {
        return generateCert(subject, List.of());
    }

    private X509Certificate generateCert(String subject, List<String> sans) {
        return ExtendedCertificateUtils.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, sans);
    }

    private static X509Certificate createSelfSignedCaCert(KeyPair kp) throws Exception {
        X500Name issuer = new X500Name("CN=TestCA");
        BigInteger serial = BigInteger.ONE;
        Date now = new Date(System.currentTimeMillis() - 3600000); // 1 hour ago
        Date later = new Date(System.currentTimeMillis() + 86400000L);

        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, serial, now, later, issuer, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder(
                        ExtendedBCCertificateUtilsProvider.getJcaContentSignerAlg(kp.getPublic()))
                .setProvider(BouncyIntegration.PROVIDER)
                .build(kp.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(BouncyIntegration.PROVIDER)
                .getCertificate(builder.build(signer));
    }

    private static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyType.RSA);
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }
}
