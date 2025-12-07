package de.adorsys.gis.keycloak.protocol.oid4vc.crypto;

import org.keycloak.common.crypto.CertificateUtilsProvider;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public interface ExtendedCertificateUtilsProvider extends CertificateUtilsProvider {

    /**
     * Generates version 3 {@link java.security.cert.X509Certificate}
     * with support for Subject Alternative Names (SANs).
     *
     * @param keyPair         the key pair
     * @param caPrivateKey    the CA private key
     * @param caCert          the CA certificate
     * @param subject         the subject name
     * @param subjectAltNames the subject alternative names
     * @return the x509 certificate
     */
    X509Certificate generateV3Certificate(
            KeyPair keyPair, PrivateKey caPrivateKey, X509Certificate caCert,
            String subject, List<String> subjectAltNames
    );
}
