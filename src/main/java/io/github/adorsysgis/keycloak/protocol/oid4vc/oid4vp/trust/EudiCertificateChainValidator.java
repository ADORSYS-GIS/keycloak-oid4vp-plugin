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
            PKIXVerificationUtil.validateLeafCertificate(chain[0]);
            return chain;
        } catch (VerificationException e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        }
    }
}
