package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.TestCryptoUtils;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.TrustMaterialRequest;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.Algorithm;

class EudiPidTrustIdentityProviderTest {

    private static final String PROVIDER_A = "PSDDE-PROVIDER-A";
    private static final String PROVIDER_B = "PSDDE-PROVIDER-B";

    @BeforeAll
    static void setupCrypto() {
        CryptoIntegration.init(EudiPidTrustIdentityProviderTest.class.getClassLoader());
    }

    @Test
    void shouldValidateChainAgainstCertificateFromTrustList() throws Exception {
        CertificateChain chain = certificateChain("Status List Signer A");
        EudiPidTrustListProvider trustListProvider = trustListProvider(snapshot(
                trustedProvider(PROVIDER_A, chain.root()),
                trustedProvider(
                        PROVIDER_B, certificateChain("Status List Signer B").root())));
        EudiPidTrustIdentityProvider provider = new EudiPidTrustIdentityProvider(config(null), trustListProvider);

        assertDoesNotThrow(() -> provider.validateX509Chain(request(), chain.encoded(), Algorithm.ES256));
    }

    @Test
    void shouldValidateLeafCertificatePublishedByTrustList() throws Exception {
        CertificateChain chain = certificateChain("Published Status List Signer");
        EudiPidTrustIdentityProvider provider = new EudiPidTrustIdentityProvider(
                config(null), trustListProvider(snapshot(trustedProvider(PROVIDER_A, chain.leaf()))));

        assertDoesNotThrow(() -> provider.validateX509Chain(request(), chain.encoded(), Algorithm.ES256));
    }

    @Test
    void shouldRejectChainNotCoveredByTrustList() throws Exception {
        CertificateChain trusted = certificateChain("Trusted Status List Signer");
        CertificateChain untrusted = certificateChain("Untrusted Status List Signer");
        EudiPidTrustIdentityProvider provider = new EudiPidTrustIdentityProvider(
                config(null), trustListProvider(snapshot(trustedProvider(PROVIDER_A, trusted.root()))));

        assertThrows(
                VerificationException.class,
                () -> provider.validateX509Chain(request(), untrusted.encoded(), Algorithm.ES256));
    }

    @Test
    void shouldRestrictTrustToConfiguredPidProvider() throws Exception {
        CertificateChain providerAChain = certificateChain("Status List Signer A");
        CertificateChain providerBChain = certificateChain("Status List Signer B");
        EudiPidTrustListProvider.TrustListSnapshot snapshot = snapshot(
                trustedProvider(PROVIDER_A, providerAChain.root()), trustedProvider(PROVIDER_B, providerBChain.root()));
        EudiPidTrustIdentityProvider provider =
                new EudiPidTrustIdentityProvider(config(PROVIDER_A), trustListProvider(snapshot));

        assertDoesNotThrow(() -> provider.validateX509Chain(request(), providerAChain.encoded(), Algorithm.ES256));
        assertThrows(
                VerificationException.class,
                () -> provider.validateX509Chain(request(), providerBChain.encoded(), Algorithm.ES256));
    }

    @Test
    void shouldRejectWhenConfiguredPidProviderIsMissing() throws Exception {
        CertificateChain chain = certificateChain("Status List Signer");
        EudiPidTrustIdentityProvider provider = new EudiPidTrustIdentityProvider(
                config("PSDDE-UNKNOWN"), trustListProvider(snapshot(trustedProvider(PROVIDER_A, chain.root()))));

        assertThrows(
                VerificationException.class,
                () -> provider.validateX509Chain(request(), chain.encoded(), Algorithm.ES256));
    }

    private static EudiPidTrustIdentityProviderConfig config(String issuer) {
        EudiPidTrustIdentityProviderConfig config = new EudiPidTrustIdentityProviderConfig();
        config.getConfig().put(EudiPidTrustIdentityProviderConfig.TRUST_LIST_URL, "https://example.test/lote.jwt");
        config.getConfig().put(EudiPidTrustIdentityProviderConfig.TRUST_LIST_SIGNING_CERTIFICATE, "unused-in-test");
        if (issuer != null) {
            config.getConfig().put(EudiPidTrustIdentityProviderConfig.ISSUER, issuer);
        }
        return config;
    }

    private static TrustMaterialRequest request() {
        return TrustMaterialRequest.builder().algorithm(Algorithm.ES256).build();
    }

    private static EudiPidTrustListProvider trustListProvider(EudiPidTrustListProvider.TrustListSnapshot snapshot)
            throws Exception {
        EudiPidTrustListProvider provider = mock(EudiPidTrustListProvider.class);
        when(provider.resolve(any())).thenReturn(snapshot);
        return provider;
    }

    private static EudiPidTrustListProvider.TrustListSnapshot snapshot(
            EudiPidTrustListProvider.TrustedPidProvider... providers) {
        List<EudiPidTrustListProvider.TrustedPidProvider> providerList = List.of(providers);
        List<X509Certificate> certificates = providerList.stream()
                .flatMap(provider -> provider.trustedCertificates().stream())
                .toList();
        return new EudiPidTrustListProvider.TrustListSnapshot(
                Instant.now().plusSeconds(3600), certificates, providerList);
    }

    private static EudiPidTrustListProvider.TrustedPidProvider trustedProvider(
            String identifier, X509Certificate certificate) {
        EudiPidTrustListProvider.TrustedPidIssuanceService service =
                new EudiPidTrustListProvider.TrustedPidIssuanceService(List.of(certificate));
        return new EudiPidTrustListProvider.TrustedPidProvider(identifier, List.of(identifier), List.of(service));
    }

    private static CertificateChain certificateChain(String subject) throws Exception {
        KeyPair rootKey = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate root = TestCryptoUtils.createSelfSignedCaCert(rootKey);
        KeyPair leafKey = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leaf = TestCryptoUtils.createLeafCert(
                leafKey, rootKey, root, "CN=" + subject, false, KeyUsage.digitalSignature);
        return new CertificateChain(leaf, root);
    }

    private record CertificateChain(X509Certificate leaf, X509Certificate root) {
        List<String> encoded() throws Exception {
            return List.of(encode(leaf), encode(root));
        }

        private static String encode(X509Certificate certificate) throws Exception {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        }
    }
}
