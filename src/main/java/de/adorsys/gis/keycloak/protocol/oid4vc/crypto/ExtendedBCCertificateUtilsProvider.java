package de.adorsys.gis.keycloak.protocol.oid4vc.crypto;

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
import org.keycloak.crypto.def.BCCertificateUtilsProvider;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Optional;

public class ExtendedBCCertificateUtilsProvider extends BCCertificateUtilsProvider
        implements ExtendedCertificateUtilsProvider {

    private static final ExtendedBCCertificateUtilsProvider INSTANCE = new ExtendedBCCertificateUtilsProvider();

    public static ExtendedBCCertificateUtilsProvider getInstance() {
        return INSTANCE;
    }

    @Override
    public X509Certificate generateV3Certificate(
            KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCert,
            String subject, List<String> subjectAltNames
    ) {
        try {
            X500Name subjectDN = new X500Name("CN=" + subject);

            // Serial Number
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            BigInteger serialNumber = BigInteger.valueOf(Math.abs(random.nextInt()));

            // Validity
            Date notBefore = new Date(System.currentTimeMillis());
            Date notAfter = new Date(System.currentTimeMillis() + (((1000L * 60 * 60 * 24 * 30)) * 12) * 3);

            // SubjectPublicKeyInfo
            SubjectPublicKeyInfo subjPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

            X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(new X500Name(caCert.getSubjectDN().getName()),
                    serialNumber, notBefore, notAfter, subjectDN, subjPubKeyInfo);

            JcaX509ExtensionUtils x509ExtensionUtils = new JcaX509ExtensionUtils();

            // Subject Key Identifier
            certGen.addExtension(Extension.subjectKeyIdentifier, false,
                    x509ExtensionUtils.createSubjectKeyIdentifier(subjPubKeyInfo));

            // Authority Key Identifier
            certGen.addExtension(Extension.authorityKeyIdentifier, false,
                    x509ExtensionUtils.createAuthorityKeyIdentifier(caCert));

            // Key Usage
            certGen.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign
                    | KeyUsage.cRLSign));

            // Extended Key Usage
            KeyPurposeId[] EKU = new KeyPurposeId[2];
            EKU[0] = KeyPurposeId.id_kp_emailProtection;
            EKU[1] = KeyPurposeId.id_kp_serverAuth;

            certGen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(EKU));

            // Basic Constraints
            certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));

            // Subject Alternative Names
            GeneralName[] names = Optional.ofNullable(subjectAltNames)
                    .orElseGet(Collections::emptyList).stream()
                    .filter(s -> s != null && !s.isBlank())
                    .map(san -> new GeneralName(GeneralName.dNSName, san))
                    .toArray(GeneralName[]::new);
            certGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));

            // Content Signer
            ContentSigner sigGen;
            if (caCert.getPublicKey().getAlgorithm().equals("EC")) {
                sigGen = new JcaContentSignerBuilder("SHA256WithECDSA").setProvider(BouncyIntegration.PROVIDER)
                        .build(caPrivateKey);
            } else {
                sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider(BouncyIntegration.PROVIDER)
                        .build(caPrivateKey);
            }

            // Certificate
            return new JcaX509CertificateConverter().setProvider(BouncyIntegration.PROVIDER).getCertificate(certGen.build(sigGen));
        } catch (Exception e) {
            throw new RuntimeException("Error creating X509v3Certificate.", e);
        }
    }
}
