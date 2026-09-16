package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;

/**
 * Tests {@link PKIXVerificationUtil} against the D-TRUST test chain in
 * {@code src/test/resources/tokenstatus/de-pid-provider-test.pem} (leaf, intermediate, root).
 *
 * <p>Trust certificates can be passed as root or as intermediate. A certificate passed as a
 * root is trusted as a root - self-signed or not - and root trust prevails if the same
 * certificate is also listed as an intermediate. The presented chain is only valid when it
 * chains up to a trusted root, using intermediates to bridge missing links. Trusting no
 * root at all is always invalid.
 */
class PKIXVerificationUtilTest {

    private static final int OCT_2026_EPOCH_SECONDS = 1790812800;

    private static X509Certificate leaf;
    private static X509Certificate intermediate;
    private static X509Certificate root;
    private static X509Certificate unrelated;
    private static List<String> chainBase64;

    @BeforeAll
    static void setup() throws Exception {
        CryptoIntegration.init(PKIXVerificationUtilTest.class.getClassLoader());
        List<X509Certificate> chain = readPemChain("/tokenstatus/de-pid-provider-test.pem");
        leaf = chain.get(0);
        intermediate = chain.get(1);
        root = chain.get(2);
        chainBase64 = chain.stream().map(PKIXVerificationUtilTest::encodeBase64).toList();

        KeyPair unrelatedKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        unrelated = TestCryptoUtils.createSelfSignedCaCert(unrelatedKeyPair);
    }

    @AfterEach
    void tearDown() {
        Time.setOffset(0);
    }

    private record ChainCase(
            String name,
            List<X509Certificate> chain,
            List<X509Certificate> roots,
            List<X509Certificate> intermediates,
            boolean valid) {}

    private static List<X509Certificate> list(X509Certificate... certificates) {
        return List.of(certificates);
    }

    static Stream<ChainCase> chainCases() {
        return Stream.of(
                // VALID: the chain reaches a trusted root
                new ChainCase("self-signed chain with self-signed root", list(root), list(root), list(), true),
                new ChainCase("leaf chain trusted as root", list(leaf), list(leaf), list(), true),
                new ChainCase("leaf chain bridged by intermediate", list(leaf), list(root), list(intermediate), true),
                new ChainCase("leaf chain bridged despite unrelated intermediate", list(leaf), list(root), list(intermediate, unrelated), true),
                new ChainCase("leaf+intermediate chain with intermediate anchor", list(leaf, intermediate), list(root), list(intermediate), true),
                new ChainCase("leaf+intermediate chain with root anchor", list(leaf, intermediate), list(root), list(), true),
                new ChainCase("leaf+intermediate chain with intermediate as root", list(leaf, intermediate), list(intermediate), list(), true),
                new ChainCase("full chain with root anchor", list(leaf, intermediate, root), list(root), list(), true),
                new ChainCase("leaf chain with intermediate as root", list(leaf), list(intermediate), list(), true),
                new ChainCase("leaf chain with intermediate and root as roots", list(leaf), list(intermediate, root), list(), true),
                new ChainCase("leaf chain with root also listed as intermediate", list(leaf), list(root), list(intermediate, root), true),
                new ChainCase("chain with certificates after the trusted root", list(leaf, intermediate, root), list(intermediate), list(), true),

                // INVALID: no trusted root, or the chain does not reach one
                new ChainCase("self-signed chain with root only as intermediate", list(root), list(), list(root), false),
                new ChainCase("leaf chain with unrelated as root anchor", list(leaf), list(unrelated), list(), false),
                new ChainCase("leaf chain with leaf only as intermediate", list(leaf), list(), list(leaf), false),
                new ChainCase("leaf chain with root anchor but no intermediate", list(leaf), list(root), list(), false),
                new ChainCase("leaf chain with unrelated cert in the middle", list(leaf, unrelated, intermediate), list(intermediate), list(), false),
                new ChainCase("leaf chain with root cert in the middle", list(leaf, root, intermediate), list(root), list(), false),
                new ChainCase("full chain with root only as intermediate", list(leaf, intermediate, root), list(), list(root), false));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("chainCases")
    void shouldValidateOnlyWhenChainReachesTrustedRoot(ChainCase testCase) {
        pinTimeToOctober2026();

        if (testCase.valid()) {
            X509Certificate[] validated = assertDoesNotThrow(() -> PKIXVerificationUtil.validateChain(
                    testCase.chain(), testCase.roots(), testCase.intermediates()));
            assertArrayEquals(testCase.chain().toArray(new X509Certificate[0]), validated);
        } else {
            assertThrows(VerificationException.class, () -> PKIXVerificationUtil.validateChain(
                    testCase.chain(), testCase.roots(), testCase.intermediates()));
        }
    }

    @Test
    void shouldRejectChainWithMatchingNamesButInvalidSignature() throws Exception {
        // Two CAs share the same subject DN (CN=TestCA) but hold different keys. The leaf is signed
        // by the first CA; presenting the second CA as the trusted root matches by name, so the
        // order check passes, but signature verification must still reject the chain.
        KeyPair firstCaKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate firstCa = TestCryptoUtils.createSelfSignedCaCert(firstCaKeyPair);

        KeyPair secondCaKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate secondCa = TestCryptoUtils.createSelfSignedCaCert(secondCaKeyPair);

        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leafCert = TestCryptoUtils.createLeafCert(leafKeyPair, firstCaKeyPair, firstCa, "CN=Leaf");

        // leafCert.issuer (CN=TestCA) == secondCa.subject (CN=TestCA) passes the order check, but
        // secondCa's public key does not verify the leaf's signature.
        VerificationException error = assertThrows(VerificationException.class,
                () -> PKIXVerificationUtil.validateChain(list(leafCert, secondCa), list(secondCa), list()));

        assertEquals("Certificate chain validation failed", error.getMessage());
    }

    @Test
    void shouldValidateChainWithValidSignature() throws Exception {
        KeyPair caKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate caCert = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);

        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leafCert = TestCryptoUtils.createLeafCert(leafKeyPair, caKeyPair, caCert, "CN=Leaf");

        X509Certificate[] validated = assertDoesNotThrow(() ->
                PKIXVerificationUtil.validateChain(list(leafCert), list(caCert), list()));

        assertArrayEquals(new X509Certificate[] {leafCert}, validated);
    }

    @Test
    void shouldRejectWhenTrailingCertificateDoesNotSignTrustedRoot() throws Exception {
        // The presented chain is [leaf, intermediate, bogusRoot] with the intermediate trusted
        // as root. bogusRoot shares the intermediate's issuer DN but does NOT sign it, so the
        // trailing certificate is a bogus certificate beyond the trusted root.
        KeyPair rootKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate root = TestCryptoUtils.createSelfSignedCaCert(rootKeyPair);

        KeyPair intermediateKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate intermediate = TestCryptoUtils.createLeafCert(
                intermediateKeyPair, rootKeyPair, root, "CN=Intermediate", true,
                KeyUsage.keyCertSign | KeyUsage.digitalSignature);

        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leaf = TestCryptoUtils.createLeafCert(leafKeyPair, intermediateKeyPair, intermediate, "CN=Leaf");

        KeyPair bogusKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate bogusRoot = TestCryptoUtils.createSelfSignedCaCert(bogusKeyPair);

        assertThrows(VerificationException.class, () -> PKIXVerificationUtil.validateChain(
                list(leaf, intermediate, bogusRoot), list(intermediate), list()));
    }

    @Test
    void shouldRejectWhenTrustingAnUnrelatedAnchor() {
        pinTimeToOctober2026();

        VerificationException error = assertThrows(VerificationException.class,
                () -> PKIXVerificationUtil.validateChain(chain(), list(unrelated), list()));

        assertEquals("Certificate chain validation failed", error.getMessage());
    }

    @Test
    void shouldRejectChainWithoutAnyTrustAnchors() {
        pinTimeToOctober2026();

        VerificationException error = assertThrows(VerificationException.class,
                () -> PKIXVerificationUtil.validateChain(chain(), list(), list()));

        assertTrue(error.getMessage().contains("No trusted root certificates available for validation"));
    }

    @Test
    void shouldValidateWhenRootAndIntermediateAreProvidedSeparately() {
        pinTimeToOctober2026();

        // Mirrors the production path: the truststore exposes the root as a trust anchor
        // and the intermediate separately, so the validator must bridge the chain.
        X509Certificate[] validated = assertDoesNotThrow(() -> PKIXVerificationUtil.validateBase64Chain(
                chainBase64, trustProvider(list(root), list(intermediate))));

        assertArrayEquals(chain().toArray(new X509Certificate[0]), validated);
    }

    @Test
    void shouldValidateLeafIntermediateChainWithRootAndIntermediateProvidedSeparately() {
        pinTimeToOctober2026();

        // The presented chain omits the root; the provider still supplies it as the trust
        // anchor and the intermediate as a bridging certificate.
        X509Certificate[] validated = assertDoesNotThrow(() -> PKIXVerificationUtil.validateBase64Chain(
                List.of(chainBase64.getFirst(), chainBase64.get(1)),
                trustProvider(list(root), list(intermediate))));

        assertEquals(2, validated.length);
        assertEquals(leaf, validated[0]);
        assertEquals(intermediate, validated[1]);
    }

    private static List<X509Certificate> chain() {
        return List.of(leaf, intermediate, root);
    }

    private void pinTimeToOctober2026() {
        long offsetSeconds = OCT_2026_EPOCH_SECONDS - System.currentTimeMillis() / 1000;
        Time.setOffset((int) offsetSeconds);
    }

    private static TrustAnchorProvider trustProvider(
            List<X509Certificate> roots, List<X509Certificate> intermediates) {
        Function<List<X509Certificate>, Map<X500Principal, List<X509Certificate>>> groupBySubject =
                certs -> certs.stream().collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal));
        return new TrustAnchorProvider() {
            @Override
            public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
                return groupBySubject.apply(roots);
            }

            @Override
            public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
                return groupBySubject.apply(intermediates);
            }
        };
    }

    private static List<X509Certificate> readPemChain(String resource) throws Exception {
        try (InputStream stream = PKIXVerificationUtilTest.class.getResourceAsStream(resource)) {
            if (stream == null) {
                throw new IllegalArgumentException("Resource not found: " + resource);
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return new ArrayList<>(cf.generateCertificates(stream).stream()
                    .map(X509Certificate.class::cast)
                    .toList());
        }
    }

    private static String encodeBase64(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}