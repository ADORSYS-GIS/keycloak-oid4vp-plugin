package de.adorsys.gis.keycloak.protocol.oid4vc.crypto;

import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.crypto.CryptoProvider;
import org.keycloak.common.util.CertificateUtils;
import org.keycloak.crypto.def.BCCertificateUtilsProvider;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

public class ExtendedCertificateUtils extends CertificateUtils {

    public static ExtendedCertificateUtilsProvider getExtendedCertificateUtilsProvider() {
        // FIXME: Overriding DefaultCryptoProvider from an extension does not work as expected.
        //  This swapping logic constitutes a reliable workaround. On the other hand, it also
        //  helps isolating the effect of ExtendedCertificateUtilsProvider to the logic in this
        //  extension only, avoiding unintended side effects on other Keycloak components.

        CryptoProvider cryptoProvider = CryptoIntegration.getProvider();
        var certUtilsProviderClass = Optional.ofNullable(cryptoProvider)
                .map(CryptoProvider::getCertificateUtils)
                .map(Object::getClass)
                .orElseThrow(() -> new IllegalStateException("CryptoProvider is not initialized properly"));

        // TODO: Add support for other CryptoProviders (Elytron / FIPS)

        if (certUtilsProviderClass == BCCertificateUtilsProvider.class) {
            return ExtendedBCCertificateUtilsProvider.getInstance();
        } else {
            String message = "ExtendedCertificateUtilsProvider is not supported by the configured CryptoProvider: "
                    + certUtilsProviderClass.getName();
            throw new UnsupportedOperationException(message);
        }
    }

    public static X509Certificate generateV3Certificate(
            PrivateKey caPrivateKey, X509Certificate caCert,
            String subject, List<String> subjectAltNames
    ) {
        return getExtendedCertificateUtilsProvider()
                .generateV3Certificate(
                        caPrivateKey, caCert,
                        subject, subjectAltNames
                );
    }
}
