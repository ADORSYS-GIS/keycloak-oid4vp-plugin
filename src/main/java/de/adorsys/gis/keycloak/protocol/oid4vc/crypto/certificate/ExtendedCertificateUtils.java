package de.adorsys.gis.keycloak.protocol.oid4vc.crypto.certificate;

import org.keycloak.common.crypto.CertificateUtilsProvider;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.CertificateUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public class ExtendedCertificateUtils extends CertificateUtils {

    public static X509Certificate generateV3Certificate(
            KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCert,
            String subject, List<String> subjectAltNames
    ) throws Exception {
        CertificateUtilsProvider certUtilsProvider = CryptoIntegration.getProvider().getCertificateUtils();
        if (!(certUtilsProvider instanceof ExtendedCertificateUtilsProvider extCertUtilsProvider)) {
            String message = "Certificate generation with SANs is not supported by the configured CryptoProvider: "
                    + CryptoIntegration.getProvider().getClass().getName();
            throw new UnsupportedOperationException(message);
        }

        return extCertUtilsProvider.generateV3Certificate(
                keyPair, caPrivateKey, caCert,
                subject, subjectAltNames
        );
    }
}
