package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.keycloak.common.VerificationException;

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

    private void validateLeafCertificate(X509Certificate leaf) throws EudiPidTrustException {
        if (leaf.getBasicConstraints() != -1) {
            throw new EudiPidTrustException("Credential issuer leaf certificate must not be a CA");
        }
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null && !keyUsage[0]) {
            throw new EudiPidTrustException("Credential issuer leaf certificate missing digitalSignature usage");
        }
    }
}
