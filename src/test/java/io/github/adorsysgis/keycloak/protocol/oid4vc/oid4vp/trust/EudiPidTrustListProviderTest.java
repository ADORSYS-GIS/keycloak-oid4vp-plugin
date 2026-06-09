package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.TestCryptoUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.models.KeycloakSession;

class EudiPidTrustListProviderTest {

    @BeforeAll
    static void setupCrypto() {
        CryptoIntegration.init(EudiPidTrustListProviderTest.class.getClassLoader());
    }

    @Test
    void shouldResolvePidIssuanceCertificatesFromTrustedLoteJwt() throws Exception {
        KeyPair signerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate signerCertificate = TestCryptoUtils.createSelfSignedCaCert(signerKeyPair);
        KeyPair issuerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate issuerCertificate =
                TestCryptoUtils.createLeafCert(issuerKeyPair, signerKeyPair, signerCertificate, "CN=PID Issuer");

        TrustPolicy policy = policy(signerCertificate);
        String trustListJwt =
                trustListJwt(signerCertificate, issuerCertificate, Instant.now().plusSeconds(3600));
        EudiPidTrustListProvider provider = new StubTrustListProvider(trustListJwt, true);

        EudiPidTrustListProvider.TrustListSnapshot snapshot = provider.resolve(policy);

        assertEquals(1, snapshot.trustedIssuerCertificates().size());
        assertEquals(issuerCertificate, snapshot.trustedIssuerCertificates().get(0));
    }

    @Test
    void shouldRejectExpiredTrustList() throws Exception {
        KeyPair signerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate signerCertificate = TestCryptoUtils.createSelfSignedCaCert(signerKeyPair);
        KeyPair issuerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate issuerCertificate =
                TestCryptoUtils.createLeafCert(issuerKeyPair, signerKeyPair, signerCertificate, "CN=PID Issuer");

        TrustPolicy policy = policy(signerCertificate);
        String trustListJwt =
                trustListJwt(signerCertificate, issuerCertificate, Instant.now().minusSeconds(60));
        EudiPidTrustException error = assertThrows(
                EudiPidTrustException.class, () -> new StubTrustListProvider(trustListJwt, true).resolve(policy));

        assertEquals("EUDI PID trust list is expired", error.getMessage());
    }

    @Test
    void shouldRejectTrustListSignedByUnexpectedCertificate() throws Exception {
        KeyPair configuredSignerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate configuredSignerCertificate = TestCryptoUtils.createSelfSignedCaCert(configuredSignerKeyPair);
        KeyPair headerSignerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate headerSignerCertificate = TestCryptoUtils.createSelfSignedCaCert(headerSignerKeyPair);
        KeyPair issuerKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate issuerCertificate = TestCryptoUtils.createLeafCert(
                issuerKeyPair, headerSignerKeyPair, headerSignerCertificate, "CN=PID Issuer");

        TrustPolicy policy = policy(configuredSignerCertificate);
        String trustListJwt = trustListJwt(
                headerSignerCertificate, issuerCertificate, Instant.now().plusSeconds(3600));
        EudiPidTrustException error = assertThrows(
                EudiPidTrustException.class, () -> new StubTrustListProvider(trustListJwt, true).resolve(policy));

        assertEquals("EUDI trust list signer does not match configured LoTE signing certificate", error.getMessage());
    }

    private TrustPolicy policy(X509Certificate signerCertificate) throws Exception {
        return new TrustPolicy()
                .setType(TrustPolicy.EUDI_PID_TRUST_LIST)
                .setTrustListUrl("https://example.test/pid-provider.jwt")
                .setTrustListSigningCertificate(encodeCertificate(signerCertificate));
    }

    private String trustListJwt(
            X509Certificate signerCertificate, X509Certificate issuerCertificate, Instant nextUpdate) throws Exception {
        String header = """
                {"typ":"trustlist+jwt","alg":"ES256","x5c":["%s"]}
                """.formatted(encodeCertificate(signerCertificate));
        String payload = """
                {
                  "LoTE": {
                    "ListAndSchemeInformation": { "NextUpdate": "%s" },
                    "TrustedEntitiesList": [
                      {
                        "TrustedEntityServices": [
                          {
                            "ServiceInformation": {
                              "ServiceTypeIdentifier": "%s",
                              "ServiceDigitalIdentity": {
                                "X509Certificates": [ { "val": "%s" } ]
                              }
                            }
                          }
                        ]
                      }
                    ]
                  }
                }
                """.formatted(
                nextUpdate, EudiPidTrustListProvider.PID_ISSUANCE_SERVICE_TYPE, encodeCertificate(issuerCertificate));

        return base64Url(header) + "." + base64Url(payload) + "." + base64Url("signature");
    }

    private String encodeCertificate(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static class StubTrustListProvider extends EudiPidTrustListProvider {

        private final String trustListJwt;
        private final boolean signatureValid;

        StubTrustListProvider(String trustListJwt, boolean signatureValid) {
            super(mock(KeycloakSession.class));
            this.trustListJwt = trustListJwt;
            this.signatureValid = signatureValid;
        }

        @Override
        protected String fetchTrustList(String url) {
            return trustListJwt;
        }

        @Override
        SignatureVerifierContext verifier(String alg, X509Certificate certificate) {
            assertEquals(Algorithm.ES256, alg);
            return new SignatureVerifierContext() {
                @Override
                public String getKid() {
                    return null;
                }

                @Override
                public String getAlgorithm() {
                    return alg;
                }

                @Override
                public boolean verify(byte[] data, byte[] signature) throws VerificationException {
                    return signatureValid;
                }
            };
        }
    }
}
