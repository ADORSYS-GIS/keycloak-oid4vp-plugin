package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.KeyType;

/**
 * Common cryptographic utilities for testing.
 */
class TestCryptoUtils {

    public static class ECCurves {
        public static final String SECP256R1 = "secp256r1";
        public static final String SECP384R1 = "secp384r1";
        public static final String SECP521R1 = "secp521r1";
    }

    static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyType.RSA);
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }

    static KeyPair generateECKeyPair(String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.EC);
        kpg.initialize(new ECGenParameterSpec(curveName));
        return kpg.generateKeyPair();
    }

    static X509Certificate createSelfSignedCaCert(KeyPair kp) throws Exception {
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
}
