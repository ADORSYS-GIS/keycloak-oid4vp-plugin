package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedBCCertificateUtilsProvider.getJcaContentSignerAlg;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.JavaAlgorithm;

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
        subKeyPair = TestCryptoUtils.generateRSAKeyPair(2048);
        caKeyPair = TestCryptoUtils.generateRSAKeyPair(2048);
        caCert = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);
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
        KeyPair ecKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate ecCaCert = TestCryptoUtils.createSelfSignedCaCert(ecKeyPair);

        X509Certificate cert = provider.generateV3Certificate(
                ecKeyPair.getPrivate(),
                ecCaCert,
                subKeyPair.getPublic(),
                "my-subject-ec",
                List.of("example.com", "www.example.com"));

        assertNotNull(cert);
        assertEquals("CN=my-subject-ec", cert.getSubjectX500Principal().getName());
        assertEquals(ecCaCert.getSubjectX500Principal(), cert.getIssuerX500Principal());
    }

    @Test
    void testGenerateV3Certificate_lifespan() {
        X509Certificate cert = provider.generateV3Certificate(
                caKeyPair.getPrivate(), caCert, subKeyPair.getPublic(), "lifespan-test", List.of());

        assertNotNull(cert);
        Date notBefore = cert.getNotBefore();
        Date notAfter = cert.getNotAfter();

        long diffMillis = notAfter.getTime() - notBefore.getTime();
        long expectedDiff = ExtendedBCCertificateUtilsProvider.DEFAULT_CERT_VALIDITY_MS;
        long buffer = ExtendedBCCertificateUtilsProvider.CLOCK_SKEW_BUFFER_MS;

        // Lifespan should be roughly 1 hour + 5 min buffer
        assertTrue(
                diffMillis >= expectedDiff && diffMillis <= expectedDiff + buffer + 1000,
                "Certificate lifespan should be approx 1 hour (plus clock skew buffer). Actual: " + diffMillis + "ms");
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
    public void testGetJcaContentSignerAlg() throws Exception {
        // Test EC curves
        testECCurve(TestCryptoUtils.ECCurves.SECP256R1, JavaAlgorithm.ES256);
        testECCurve(TestCryptoUtils.ECCurves.SECP384R1, JavaAlgorithm.ES384);
        testECCurve(TestCryptoUtils.ECCurves.SECP521R1, JavaAlgorithm.ES512);

        // Test RSA key sizes
        testRSAKeySize(2048, JavaAlgorithm.RS256);
        testRSAKeySize(3072, JavaAlgorithm.RS384);
        testRSAKeySize(4096, JavaAlgorithm.RS512);

        // Test RSA key too small
        KeyPair rsa1024 = TestCryptoUtils.generateRSAKeyPair(1024);
        IllegalArgumentException ex =
                assertThrows(IllegalArgumentException.class, () -> getJcaContentSignerAlg(rsa1024.getPublic()));
        assertEquals("RSA key size too small: 1024 bits (minimum 2048)", ex.getMessage());
    }

    private void testECCurve(String curveName, String expectedAlgorithm) throws Exception {
        KeyPair keyPair = TestCryptoUtils.generateECKeyPair(curveName);
        assertEquals(expectedAlgorithm, getJcaContentSignerAlg(keyPair.getPublic()));
    }

    private void testRSAKeySize(int keySize, String expectedAlgorithm) throws Exception {
        KeyPair keyPair = TestCryptoUtils.generateRSAKeyPair(keySize);
        assertEquals(expectedAlgorithm, getJcaContentSignerAlg(keyPair.getPublic()));
    }
}
