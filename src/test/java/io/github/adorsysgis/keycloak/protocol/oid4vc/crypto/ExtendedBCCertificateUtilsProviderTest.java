package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedBCCertificateUtilsProvider.getJcaContentSignerAlg;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.KeyType;

class ExtendedBCCertificateUtilsProviderTest {

    private static ExtendedBCCertificateUtilsProvider provider;
    private static KeyPair subKeyPair;
    private static KeyPair caKeyPair;
    private static X509Certificate caCert;

    @BeforeAll
    static void setup() throws Exception {
        CryptoIntegration.init(ExtendedBCCertificateUtilsProviderTest.class.getClassLoader());
        provider = ExtendedBCCertificateUtilsProvider.getInstance();

        // --- Generate CA keypair and minimal certificate ---
        subKeyPair = generateRSAKeyPair(2048);
        caKeyPair = generateRSAKeyPair(2048);
        caCert = createSelfSignedCaCert(caKeyPair);
    }

    @Test
    void testGenerateV3Certificate_basicFields() {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(),
                caCert,
                subKeyPair.getPublic(),
                "my-subject",
                List.of("example.com", "www.example.com"));

        assertNotNull(cert);
        assertEquals("CN=my-subject", cert.getSubjectX500Principal().getName());
        assertEquals(caCert.getSubjectX500Principal(), cert.getIssuerX500Principal());
    }

    @Test
    void testGenerateV3Certificate_basicFields_EC() throws Exception {
        KeyPair ecCaKeyPair = generateECKeyPair(ECCurves.SECP256R1);
        X509Certificate ecCaCert = createSelfSignedCaCert(ecCaKeyPair);

        X509Certificate cert = provider.generateV3Certificate(
                ecCaKeyPair.getPrivate(),
                ecCaCert,
                subKeyPair.getPublic(),
                "my-subject-ec",
                List.of("example.com", "www.example.com"));

        assertNotNull(cert);
        assertEquals("CN=my-subject-ec", cert.getSubjectX500Principal().getName());
        assertEquals(ecCaCert.getSubjectX500Principal(), cert.getIssuerX500Principal());
    }

    @Test
    void testGenerateV3Certificate_sanExtension() throws Exception {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "test", List.of("a.com", "b.com"));

        byte[] sanBytes = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        assertNotNull(sanBytes);

        GeneralNames gns = GeneralNames.getInstance(
                ASN1Sequence.fromByteArray(ASN1OctetString.getInstance(sanBytes).getOctets()));

        GeneralName[] names = gns.getNames();
        assertEquals(2, names.length);
        assertEquals("a.com", names[0].getName().toString());
        assertEquals("b.com", names[1].getName().toString());
    }

    private static Stream<List<String>> noSanInputProvider() {
        return Stream.of(null, List.of(), List.of(""), Collections.singletonList(null));
    }

    @ParameterizedTest
    @MethodSource("noSanInputProvider")
    void testGenerateV3Certificate_NoSanExtension(List<String> subAltNames) {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "test", subAltNames);

        byte[] sanBytes = cert.getExtensionValue(Extension.subjectAlternativeName.getId());
        assertNull(sanBytes);
    }

    @Test
    void testGenerateV3Certificate_keyUsage() {
        X509Certificate cert =
                provider.generateV3Certificate(caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "ku", List.of());

        boolean[] ku = cert.getKeyUsage();

        assertNotNull(ku);
        assertEquals(9, ku.length); // X.509 always returns 9 entries

        // Indices for Java X.509 key usage
        final int DIGITAL_SIGNATURE = 0;
        final int KEY_CERT_SIGN = 5;
        final int CRL_SIGN = 6;

        // Expected true bits
        assertTrue(ku[DIGITAL_SIGNATURE], "digitalSignature must be true");
        assertTrue(ku[KEY_CERT_SIGN], "keyCertSign must be true");
        assertTrue(ku[CRL_SIGN], "cRLSign must be true");

        // All others must be false
        for (int i = 0; i < ku.length; i++) {
            if (i == DIGITAL_SIGNATURE || i == KEY_CERT_SIGN || i == CRL_SIGN) {
                continue;
            }
            assertFalse(ku[i], "KeyUsage[" + i + "] must be false");
        }
    }

    @Test
    void testGenerateV3Certificate_eku() throws Exception {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "eku", List.of());

        byte[] ekuBytes = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
        assertNotNull(ekuBytes);

        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                ASN1Sequence.fromByteArray(ASN1OctetString.getInstance(ekuBytes).getOctets()));

        assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection));
        assertTrue(eku.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
    }

    @Test
    void testGenerateV3Certificate_basicConstraints() throws Exception {
        X509Certificate cert =
                provider.generateV3Certificate(caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "bc", List.of());

        BasicConstraints bc =
                BasicConstraints.fromExtensions(new X509CertificateHolder(cert.getEncoded()).getExtensions());

        assertNotNull(bc);
        assertEquals(0, bc.getPathLenConstraint().intValue());
    }

    @Test
    void testGenerateV3Certificate_certificateIsSignedByCA() throws Exception {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "sig-check", List.of());

        // should throw no exception
        cert.verify(caKeyPair.getPublic());
    }

    @Test
    void testGenerateV3Certificate_caching() {
        String subject = "cache-test";
        List<String> sans = List.of("cache.com");

        X509Certificate cert1 =
                provider.generateV3Certificate(caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, sans);
        X509Certificate cert2 =
                provider.generateV3Certificate(caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, sans);

        assertNotNull(cert1);
        assertNotNull(cert2);
        // Check that the same instance is returned from cache
        assertSame(cert1, cert2, "Certificate should be cached and reused instance");
    }

    @Test
    void testGenerateV3Certificate_cacheMissOnDifferentParams() {
        X509Certificate cert1 = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "s1", List.of("a.com"));
        X509Certificate cert2 = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "s2", List.of("a.com"));
        X509Certificate cert3 = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "s1", List.of("b.com"));

        // Different subjects or SANs should yield different instances
        assertNotSame(cert1, cert2, "Different subjects should result in different certificates");
        assertNotSame(cert1, cert3, "Different SANs should result in different certificates");
    }

    @Test
    void testGenerateV3Certificate_cacheMissOnCaRotation() throws Exception {
        KeyPair caKeyPair2 = generateRSAKeyPair(2048);
        X509Certificate caCert2 = createSelfSignedCaCert(caKeyPair2);

        String subject = "rotation-test";

        X509Certificate cert1 = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, List.of());
        X509Certificate cert2 = provider.generateV3Certificate(
                caKeyPair2.getPrivate(), caCert2, subKeyPair.getPublic(), subject, List.of());

        // Cache should miss when CA changes
        assertNotSame(cert1, cert2, "Different CA certificates should result in different verifier certificates");
    }

    @Test
    void testGenerateV3Certificate_concurrency() throws Exception {
        String subject = "concurrency-test";
        int threadCount = 10;
        List<CompletableFuture<X509Certificate>> futures = new ArrayList<>();

        for (int i = 0; i < threadCount; i++) {
            futures.add(CompletableFuture.supplyAsync(() -> provider.generateV3Certificate(
                    caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), subject, List.of())));
        }

        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        X509Certificate firstCert = futures.get(0).get();
        for (int i = 1; i < threadCount; i++) {
            // All threads should get the exact same instance
            assertSame(firstCert, futures.get(i).get(), "All threads should receive the same cached instance");
        }
    }

    @Test
    public void testGetJcaContentSignerAlg() throws Exception {
        // Test EC curves
        testECCurve(ECCurves.SECP256R1, JavaAlgorithm.ES256);
        testECCurve(ECCurves.SECP384R1, JavaAlgorithm.ES384);
        testECCurve(ECCurves.SECP521R1, JavaAlgorithm.ES512);

        // Test RSA key sizes
        testRSAKeySize(2048, JavaAlgorithm.RS256);
        testRSAKeySize(3072, JavaAlgorithm.RS384);
        testRSAKeySize(4096, JavaAlgorithm.RS512);

        // Test RSA key too small
        KeyPair rsa1024 = generateRSAKeyPair(1024);
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> getJcaContentSignerAlg(rsa1024.getPublic()));
        assertEquals("RSA key size too small: 1024 bits (minimum 2048)", ex.getMessage());
    }

    private void testECCurve(String curveName, String expectedAlgorithm) throws Exception {
        KeyPair keyPair = generateECKeyPair(curveName);
        assertEquals(expectedAlgorithm, getJcaContentSignerAlg(keyPair.getPublic()));
    }

    private void testRSAKeySize(int keySize, String expectedAlgorithm) throws Exception {
        KeyPair keyPair = generateRSAKeyPair(keySize);
        assertEquals(expectedAlgorithm, getJcaContentSignerAlg(keyPair.getPublic()));
    }

    private static X509Certificate createSelfSignedCaCert(KeyPair kp) throws Exception {
        X500Name issuer = new X500Name("CN=TestCA");
        BigInteger serial = BigInteger.ONE;
        Date now = new Date();
        Date later = new Date(now.getTime() + 86400000L);

        X509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuer, serial, now, later, issuer, kp.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        String alg = getJcaContentSignerAlg(kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(alg)
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

    private static KeyPair generateECKeyPair(String curveName) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyType.EC);
        gen.initialize(new ECGenParameterSpec(curveName));
        return gen.generateKeyPair();
    }

    public static class ECCurves {
        public static final String SECP256R1 = "secp256r1";
        public static final String SECP384R1 = "secp384r1";
        public static final String SECP521R1 = "secp521r1";
    }
}
