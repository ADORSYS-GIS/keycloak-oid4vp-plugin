package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.ExtendedBCCertificateUtilsProvider;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyWrapper;

class ConfiguredAccessCertificateValidatorTest {

    @BeforeAll
    static void setup() {
        CryptoIntegration.init(ConfiguredAccessCertificateValidatorTest.class.getClassLoader());
    }

    @BeforeEach
    void clearCache() {
        ConfiguredAccessCertificateValidator.clearCache();
    }

    @Test
    void shouldCacheSuccessfulValidationUntilCertificateExpiry() throws Exception {
        KeyPair keyPair = generateRSAKeyPair();
        X509Certificate certificate = createSelfSignedCertificate(
                keyPair, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        KeyWrapper signingKey = toSigningKey(keyPair, "rsa-signing-kid");

        assertDoesNotThrow(() -> ConfiguredAccessCertificateValidator.validate(certificate, signingKey));
        assertEquals(1, ConfiguredAccessCertificateValidator.cacheSize());

        assertDoesNotThrow(() -> ConfiguredAccessCertificateValidator.validate(certificate, signingKey));
        assertEquals(1, ConfiguredAccessCertificateValidator.cacheSize());
    }

    @Test
    void shouldRejectCertificateIfPublicKeyDoesNotMatchSigningKey() throws Exception {
        KeyPair certificateKeyPair = generateRSAKeyPair();
        KeyPair signingKeyPair = generateRSAKeyPair();
        X509Certificate certificate = createSelfSignedCertificate(
                certificateKeyPair, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));
        KeyWrapper signingKey = toSigningKey(signingKeyPair, "rsa-signing-kid");

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> ConfiguredAccessCertificateValidator.validate(certificate, signingKey));

        assertEquals(
                "Configured access certificate does not match the active signing key 'rsa-signing-kid'",
                ex.getMessage());
        assertEquals(0, ConfiguredAccessCertificateValidator.cacheSize());
    }

    @Test
    void shouldRejectExpiredCertificate() throws Exception {
        KeyPair keyPair = generateRSAKeyPair();
        X509Certificate expiredCertificate = createSelfSignedCertificate(
                keyPair, Instant.now().minusSeconds(3600), Instant.now().minusSeconds(60));
        KeyWrapper signingKey = toSigningKey(keyPair, "rsa-signing-kid");

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> ConfiguredAccessCertificateValidator.validate(expiredCertificate, signingKey));

        assertEquals("Configured access certificate has expired", ex.getMessage());
        assertEquals(0, ConfiguredAccessCertificateValidator.cacheSize());
    }

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyType.RSA);
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyWrapper toSigningKey(KeyPair keyPair, String kid) {
        KeyWrapper keyWrapper = new KeyWrapper();
        keyWrapper.setKid(kid);
        keyWrapper.setType(KeyType.RSA);
        keyWrapper.setPublicKey(keyPair.getPublic());
        keyWrapper.setPrivateKey(keyPair.getPrivate());
        return keyWrapper;
    }

    private static X509Certificate createSelfSignedCertificate(KeyPair keyPair, Instant notBefore, Instant notAfter)
            throws Exception {
        X500Name subject = new X500Name("CN=ConfiguredAccessCertificateValidatorTest");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.ONE,
                Date.from(notBefore),
                Date.from(notAfter),
                subject,
                keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder(
                        ExtendedBCCertificateUtilsProvider.getJcaContentSignerAlg(keyPair.getPublic()))
                .setProvider(BouncyIntegration.PROVIDER)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(BouncyIntegration.PROVIDER)
                .getCertificate(builder.build(signer));
    }
}
