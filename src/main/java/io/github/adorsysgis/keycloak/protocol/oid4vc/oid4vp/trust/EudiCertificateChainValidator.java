package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.X509CertificateChainValidator;

class EudiCertificateChainValidator {

    X509Certificate[] validate(List<String> x5c, Collection<X509Certificate> trustedAnchors)
            throws EudiPidTrustException {
        try {
            X509Certificate[] chain = PKIXVerificationUtil.validateBase64Chain(x5c, trustedAnchors);
            X509Certificate leaf = chain[0];
            validateLeafCertificate(leaf);
            return chain;
        } catch (EudiPidTrustException e) {
            throw e;
        } catch (VerificationException e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        } catch (Exception e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        }
    }

    X509Certificate[] validatePublishedOrChained(List<String> x5c, Collection<X509Certificate> publishedCertificates)
            throws EudiPidTrustException {
        try {
            List<X509Certificate> presentedChain = X509CertificateChainValidator.decodeCertificateChain(x5c);
            X509Certificate leaf = presentedChain.getFirst();
            if (publishedCertificates.stream().anyMatch(leaf::equals)) {
                validatePublishedSignerCertificate(leaf);
                return presentedChain.toArray(X509Certificate[]::new);
            }

            return validate(x5c, publishedCertificates);
        } catch (EudiPidTrustException e) {
            throw e;
        } catch (VerificationException e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        }
    }

    private void validatePublishedSignerCertificate(X509Certificate certificate) throws EudiPidTrustException {
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            throw new EudiPidTrustException("The published signer certificate is not currently valid", e);
        }
        validateLeafCertificate(certificate);
    }

    private void validateLeafCertificate(X509Certificate leaf) throws EudiPidTrustException {
        if (leaf.getBasicConstraints() != -1) {
            throw new EudiPidTrustException("Credential issuer leaf certificate must not be a CA");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && (keyUsage.length == 0 || !keyUsage[0])) {
            throw new EudiPidTrustException("Credential issuer leaf certificate missing digitalSignature usage");
        }
    }
}
