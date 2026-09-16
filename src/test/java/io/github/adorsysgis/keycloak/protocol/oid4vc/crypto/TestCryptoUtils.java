package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX500NameUtil;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.KeyType;

/**
 * Common cryptographic utilities for testing.
 */
public class TestCryptoUtils {

    public static class ECCurves {
        public static final String SECP256R1 = "secp256r1";
        public static final String SECP384R1 = "secp384r1";
        public static final String SECP521R1 = "secp521r1";
    }

    public static KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(KeyType.RSA);
        gen.initialize(keySize);
        return gen.generateKeyPair();
    }

    public static KeyPair generateECKeyPair(String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.EC);
        kpg.initialize(new ECGenParameterSpec(curveName));
        return kpg.generateKeyPair();
    }

    public static X509Certificate createSelfSignedCaCert(KeyPair kp) throws Exception {
        return createLeafCert(kp, kp, null, "CN=TestCA", true, KeyUsage.digitalSignature | KeyUsage.keyCertSign);
    }

    public static X509Certificate createLeafCert(KeyPair kp, KeyPair caKp, X509Certificate caCert, String subject)
            throws Exception {
        return createLeafCert(kp, caKp, caCert, subject, false, KeyUsage.digitalSignature);
    }

    public static X509Certificate createLeafCert(
            KeyPair kp, KeyPair caKp, X509Certificate caCert, String subject, boolean isCa, Integer keyUsageBitmask)
            throws Exception {
        Date now = new Date(System.currentTimeMillis() - 3600000);
        Date later = new Date(System.currentTimeMillis() + 86400000L);
        return createLeafCert(kp, caKp, caCert, subject, isCa, keyUsageBitmask, now, later);
    }

    public static X509Certificate createLeafCert(
            KeyPair kp,
            KeyPair caKp,
            X509Certificate caCert,
            String subject,
            boolean isCa,
            Integer keyUsageBitmask,
            Date notBefore,
            Date notAfter)
            throws Exception {
        // The names are taken from principals directly so the encoded attribute order is
        // preserved. A string round trip (new X500Name(principal.getName())) reverses
        // multi-RDN names and breaks byte-level DN equality with the issuer certificate.
        X500Name subjectName = JcaX500NameUtil.getX500Name(new X500Principal(subject));
        X500Name issuerName =
                caCert != null ? JcaX500NameUtil.getX500Name(caCert.getSubjectX500Principal()) : subjectName;
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());

        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(issuerName, serial, notBefore, notAfter, subjectName, kp.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        if (keyUsageBitmask != null) {
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsageBitmask));
        }

        ContentSigner signer = new JcaContentSignerBuilder(
                        ExtendedBCCertificateUtilsProvider.getJcaContentSignerAlg(caKp.getPublic()))
                .setProvider(BouncyIntegration.PROVIDER)
                .build(caKp.getPrivate());

        return new JcaX509CertificateConverter()
                .setProvider(BouncyIntegration.PROVIDER)
                .getCertificate(builder.build(signer));
    }
}
