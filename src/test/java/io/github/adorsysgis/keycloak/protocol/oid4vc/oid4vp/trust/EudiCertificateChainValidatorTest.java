package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.TestCryptoUtils;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;

class EudiCertificateChainValidatorTest {

    @BeforeAll
    static void setupCrypto() {
        CryptoIntegration.init(EudiCertificateChainValidatorTest.class.getClassLoader());
    }

    @Test
    void shouldAcceptIssuerLeafChainedToTrustedPidCertificate() throws Exception {
        KeyPair caKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate caCertificate = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);
        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leafCertificate =
                TestCryptoUtils.createLeafCert(leafKeyPair, caKeyPair, caCertificate, "CN=PID Issuer");

        X509Certificate[] validated = new EudiCertificateChainValidator()
                .validate(x5c(leafCertificate, caCertificate), List.of(caCertificate));

        assertEquals(2, validated.length);
        assertEquals(leafCertificate, validated[0]);
        assertEquals(caCertificate, validated[1]);
    }

    @Test
    void shouldRejectIssuerLeafWithoutDigitalSignatureUsage() throws Exception {
        KeyPair caKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate caCertificate = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);
        KeyPair leafKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate leafCertificate = TestCryptoUtils.createLeafCert(
                leafKeyPair, caKeyPair, caCertificate, "CN=PID Issuer", false, KeyUsage.keyAgreement);

        EudiPidTrustException error =
                assertThrows(EudiPidTrustException.class, () -> new EudiCertificateChainValidator()
                        .validate(x5c(leafCertificate, caCertificate), List.of(caCertificate)));

        assertEquals("Credential issuer leaf certificate missing digitalSignature usage", error.getMessage());
    }

    @Test
    void shouldRejectIssuerLeafThatIsACaCertificate() throws Exception {
        KeyPair caKeyPair = TestCryptoUtils.generateECKeyPair(TestCryptoUtils.ECCurves.SECP256R1);
        X509Certificate caCertificate = TestCryptoUtils.createSelfSignedCaCert(caKeyPair);

        EudiPidTrustException error =
                assertThrows(EudiPidTrustException.class, () -> new EudiCertificateChainValidator()
                        .validate(x5c(caCertificate), List.of(caCertificate)));

        assertEquals("Credential issuer leaf certificate must not be a CA", error.getMessage());
    }

    private List<String> x5c(X509Certificate... certificates) throws Exception {
        return java.util.Arrays.stream(certificates)
                .map(this::encodeCertificate)
                .toList();
    }

    private String encodeCertificate(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
