package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import org.keycloak.common.crypto.CertificateUtilsProvider;

public interface ExtendedCertificateUtilsProvider extends CertificateUtilsProvider {

    /**
     * Generates version 3 {@link java.security.cert.X509Certificate}
     * with support for Subject Alternative Names (SANs).
     *
     * @param caPrivateKey    the CA private key
     * @param caCert          the CA certificate
     * @param subPublicKey    the subject public key
     * @param subject         the subject name
     * @param subjectAltNames the subject alternative names
     * @return the x509 certificate
     */
    X509Certificate generateV3Certificate(
            PrivateKey caPrivateKey,
            X509Certificate caCert,
            PublicKey subPublicKey,
            String subject,
            List<String> subjectAltNames);

    /**
     * Creates a PEM-encoded PKCS#10 certificate signing request.
     *
     * @param privateKey the private key signing the request
     * @param publicKey the public key to certify
     * @param algorithm the JOSE algorithm of the signing key
     * @param commonName the subject common name
     * @return the PEM-encoded certificate signing request
     */
    String generateCsr(PrivateKey privateKey, PublicKey publicKey, String algorithm, String commonName);
}
