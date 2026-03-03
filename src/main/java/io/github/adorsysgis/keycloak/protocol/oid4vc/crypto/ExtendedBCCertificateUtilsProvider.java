package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.keycloak.common.util.BouncyIntegration;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.def.BCCertificateUtilsProvider;

public class ExtendedBCCertificateUtilsProvider extends BCCertificateUtilsProvider
        implements ExtendedCertificateUtilsProvider {

    private static final ExtendedBCCertificateUtilsProvider INSTANCE = new ExtendedBCCertificateUtilsProvider();
    public static final int SECURE_RANDOM_ENTROPY = 20;

    public static ExtendedBCCertificateUtilsProvider getInstance() {
        return INSTANCE;
    }

    @Override
    public X509Certificate generateV3Certificate(
            PrivateKey caPrivateKey,
            X509Certificate caCert,
            PublicKey subPublicKey,
            String subject,
            List<String> subjectAltNames) {
        try {
            return generateNewCertificate(caPrivateKey, caCert, subPublicKey, subject, subjectAltNames);
        } catch (Exception e) {
            throw new RuntimeException("Error creating X509v3Certificate.", e);
        }
    }

    private X509Certificate generateNewCertificate(
            PrivateKey caPrivateKey,
            X509Certificate caCert,
            PublicKey subPublicKey,
            String subject,
            List<String> subjectAltNames)
            throws Exception {
        X500Name subjectDN = new X500Name("CN=" + subject);

        // Validity
        Date notBefore = caCert.getNotBefore();
        Date notAfter = caCert.getNotAfter();

        // SubjectPublicKeyInfo
        SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfo.getInstance(subPublicKey.getEncoded());

        // Certificate Builder
        BigInteger serialNumber = generateSerialNumber();
        X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(
                new X500Name(caCert.getSubjectX500Principal().getName()),
                serialNumber,
                notBefore,
                notAfter,
                subjectDN,
                subjPubKeyInfo);

        // Subject Key Identifier
        JcaX509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();
        certGen.addExtension(
                Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

        // Authority Key Identifier
        certGen.addExtension(
                Extension.authorityKeyIdentifier, false, x509ExtensionUtils.createAuthorityKeyIdentifier(caCert));

        // Key Usage
        int keyUsageBits = KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.cRLSign;
        certGen.addExtension(Extension.keyUsage, false, new KeyUsage(keyUsageBits));

        // Extended Key Usage
        KeyPurposeId[] EKU = new KeyPurposeId[2];
        EKU[0] = KeyPurposeId.id_kp_emailProtection;
        EKU[1] = KeyPurposeId.id_kp_serverAuth;
        certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(EKU));

        // Basic Constraints
        certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

        // Subject Alternative Names
        GeneralName[] names = Optional.ofNullable(subjectAltNames).orElseGet(Collections::emptyList).stream()
                .filter(s -> s != null && !s.isBlank())
                .map(san -> new GeneralName(GeneralName.dNSName, san))
                .toArray(GeneralName[]::new);
        if (names.length > 0) {
            certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
        }

        // Content Signer
        String jcaContentSignerAlg = getJcaContentSignerAlg(caCert.getPublicKey());
        ContentSigner sigGen = new JcaContentSignerBuilder(jcaContentSignerAlg)
                .setProvider(BouncyIntegration.PROVIDER)
                .build(caPrivateKey);

        // Certificate
        return new JcaX509CertificateConverter()
                .setProvider(BouncyIntegration.PROVIDER)
                .getCertificate(certGen.build(sigGen));
    }

    public static String getJcaContentSignerAlg(PublicKey publicKey) {
        switch (publicKey) {
            // Handle EC keys - select algorithm based on curve size
            case ECPublicKey ecKey -> {
                int curveSize = ecKey.getParams().getCurve().getField().getFieldSize();

                return switch (curveSize) {
                    case 256 -> JavaAlgorithm.ES256; // P-256 / secp256r1
                    case 384 -> JavaAlgorithm.ES384; // P-384 / secp384r1
                    case 521 -> JavaAlgorithm.ES512; // P-521 / secp521r1
                    default -> throw new IllegalArgumentException("Unsupported EC curve size: " + curveSize + " bits");
                };
            }

            // Handle RSA keys - select algorithm based on key size
            case RSAPublicKey rsaKey -> {
                int keySize = rsaKey.getModulus().bitLength();

                if (keySize < 2048) {
                    throw new IllegalArgumentException("RSA key size too small: " + keySize + " bits (minimum 2048)");
                }

                if (keySize >= 4096) return JavaAlgorithm.RS512; // SHA-512
                if (keySize >= 3072) return JavaAlgorithm.RS384; // SHA-384
                return JavaAlgorithm.RS256; // SHA-256  // SHA-384
            }

            // Other key types are not supported
            default ->
                throw new IllegalArgumentException(
                        "Unsupported key type: " + publicKey.getClass().getSimpleName());
        }
    }

    private BigInteger generateSerialNumber() {
        byte[] buf = new byte[SECURE_RANDOM_ENTROPY];
        new SecureRandom().nextBytes(buf);
        return new BigInteger(1, buf);
    }
}
