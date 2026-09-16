package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
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

    // Locally generated trust anchors sharing a de-pid chain issuer DN, valid around the
    // pinned validation date.
    private static X509Certificate sameDnCa;
    private static X509Certificate bogusRoot;

    @BeforeAll
    static void setup() throws Exception {
        CryptoIntegration.init(PKIXVerificationUtilTest.class.getClassLoader());
        List<X509Certificate> chain = readPemChain("/tokenstatus/de-pid-provider-test.pem");
        leaf = chain.get(0);
        intermediate = chain.get(1);
        root = chain.get(2);

        // An unrelated certificate for testing scenarios
        KeyPair unrelatedKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        unrelated = TestCryptoUtils.createSelfSignedCaCert(unrelatedKeyPair);

        // Trust anchors whose subjects match a de-pid chain issuer DN but hold a different
        // key, so the presented-chain order step passes by name and the signature check has
        // to reject the link.
        Date notBefore = oct2026(-32);
        Date notAfter = oct2026(32);
        KeyPair sameDnCaKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        sameDnCa = TestCryptoUtils.createLeafCert(
                sameDnCaKeyPair,
                sameDnCaKeyPair,
                null,
                intermediate.getSubjectX500Principal().getName(),
                true,
                KeyUsage.keyCertSign | KeyUsage.digitalSignature,
                notBefore,
                notAfter);
        KeyPair bogusRootKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        bogusRoot = TestCryptoUtils.createLeafCert(
                bogusRootKeyPair,
                bogusRootKeyPair,
                null,
                root.getSubjectX500Principal().getName(),
                true,
                KeyUsage.keyCertSign | KeyUsage.digitalSignature,
                notBefore,
                notAfter);
    }

    @AfterEach
    void tearDown() {
        Time.setOffset(0);
    }

    private void pinTimeToOctober2026() {
        long offsetSeconds = OCT_2026_EPOCH_SECONDS - System.currentTimeMillis() / 1000;
        Time.setOffset((int) offsetSeconds);
    }

    private static Date oct2026(long dayOffset) {
        return new Date((OCT_2026_EPOCH_SECONDS + dayOffset * 86400) * 1000);
    }

    private static List<X509Certificate> chain() {
        return list(leaf, intermediate, root);
    }

    private static List<X509Certificate> list(X509Certificate... certificates) {
        return List.of(certificates);
    }

    private record ChainCase(
            String name,
            List<X509Certificate> chain,
            List<X509Certificate> roots,
            List<X509Certificate> intermediates,
            String expectedMessage) {}

    private static ChainCase valid(
            String name,
            List<X509Certificate> chain,
            List<X509Certificate> roots,
            List<X509Certificate> intermediates) {
        return new ChainCase(name, chain, roots, intermediates, null);
    }

    private static ChainCase invalid(
            String name,
            List<X509Certificate> chain,
            List<X509Certificate> roots,
            List<X509Certificate> intermediates,
            String expectedMessage) {
        return new ChainCase(name, chain, roots, intermediates, expectedMessage);
    }

    static Stream<ChainCase> chainCases() {
        return Stream.concat(validCases(), invalidCases());
    }

    static Stream<ChainCase> validCases() {
        return Stream.of(
                // VALID: the chain reaches a trusted root
                valid("self-signed chain with self-signed root", list(root), list(root), list()),
                valid("leaf chain trusted as root", list(leaf), list(leaf), list()),
                valid("leaf chain bridged by intermediate", list(leaf), list(root), list(intermediate)),
                valid(
                        "leaf chain bridged despite unrelated intermediate",
                        list(leaf),
                        list(root),
                        list(intermediate, unrelated)),
                valid(
                        "leaf+intermediate chain with intermediate anchor",
                        list(leaf, intermediate),
                        list(root),
                        list(intermediate)),
                valid("leaf+intermediate chain with root anchor", list(leaf, intermediate), list(root), list()),
                valid(
                        "leaf+intermediate chain with intermediate as root",
                        list(leaf, intermediate),
                        list(intermediate),
                        list()),
                valid("full chain with root anchor", list(leaf, intermediate, root), list(root), list()),
                valid(
                        "full chain with root and intermediate anchors",
                        list(leaf, intermediate, root),
                        list(root),
                        list(intermediate)),
                valid("leaf chain with intermediate as root", list(leaf), list(intermediate), list()),
                valid("leaf chain with intermediate and root as roots", list(leaf), list(intermediate, root), list()),
                valid(
                        "leaf chain with root also listed as intermediate",
                        list(leaf),
                        list(root),
                        list(intermediate, root)),
                valid(
                        "chain with certificates after the trusted root",
                        list(leaf, intermediate, root),
                        list(intermediate),
                        list()));
    }

    static Stream<ChainCase> invalidCases() {
        return Stream.of(
                // INVALID: no trusted root
                invalid(
                        "self-signed chain with root only as intermediate",
                        list(root),
                        list(),
                        list(root),
                        "No trusted root certificates available for validation"),
                invalid(
                        "leaf chain with leaf only as intermediate",
                        list(leaf),
                        list(),
                        list(leaf),
                        "No trusted root certificates available for validation"),
                invalid(
                        "full chain with root only as intermediate",
                        list(leaf, intermediate, root),
                        list(),
                        list(root),
                        "No trusted root certificates available for validation"),
                invalid(
                        "full chain without any trust anchors",
                        chain(),
                        list(),
                        list(),
                        "No trusted root certificates available for validation"),

                // INVALID: the chain does not reach the trusted root
                invalid(
                        "leaf chain with unrelated as root anchor",
                        list(leaf),
                        list(unrelated),
                        list(),
                        "Certificate chain validation failed"),
                invalid(
                        "leaf chain with root anchor but no intermediate",
                        list(leaf),
                        list(root),
                        list(),
                        "Certificate chain validation failed"),
                invalid(
                        "full chain with unrelated as root anchor",
                        chain(),
                        list(unrelated),
                        list(),
                        "Certificate chain validation failed"),

                // INVALID: the presented chain is incoherent
                invalid(
                        "leaf chain with unrelated cert in the middle",
                        list(leaf, unrelated, intermediate),
                        list(intermediate),
                        list(),
                        "Certificate chain is not in order"),
                invalid(
                        "leaf chain with root cert in the middle",
                        list(leaf, root, intermediate),
                        list(root),
                        list(),
                        "Certificate chain is not in order"),
                invalid(
                        "leaf chain with same subject CA that does not sign it",
                        list(leaf, sameDnCa),
                        list(sameDnCa),
                        list(),
                        "Certificate chain signature validation failed"),
                invalid(
                        "chain with bogus root beyond the trusted root",
                        list(leaf, intermediate, bogusRoot),
                        list(intermediate),
                        list(),
                        "Certificate chain signature validation failed"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("chainCases")
    void shouldValidateOnlyWhenChainReachesTrustedRoot(ChainCase testCase) {
        pinTimeToOctober2026();

        if (testCase.expectedMessage() == null) {
            X509Certificate[] validated = assertDoesNotThrow(() ->
                    PKIXVerificationUtil.validateChain(testCase.chain(), testCase.roots(), testCase.intermediates()));
            assertArrayEquals(testCase.chain().toArray(new X509Certificate[0]), validated);
        } else {
            VerificationException error = assertThrows(
                    VerificationException.class,
                    () -> PKIXVerificationUtil.validateChain(
                            testCase.chain(), testCase.roots(), testCase.intermediates()));
            assertEquals(testCase.expectedMessage(), error.getMessage());
        }
    }

    @SuppressWarnings("SameParameterValue")
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
}
