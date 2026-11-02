package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil.LeafCertificateValidationException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import org.keycloak.common.VerificationException;

class EudiCertificateChainValidator {

    X509Certificate[] validate(List<String> x5c, Collection<X509Certificate> trustedAnchors)
            throws EudiPidTrustException {
        try {
            List<X509Certificate> presentedChain = PKIXVerificationUtil.decodeBase64Chain(x5c);
            return PKIXVerificationUtil.validateSigningChainToRoots(presentedChain, trustedAnchors);
        } catch (LeafCertificateValidationException e) {
            String message =
                    switch (e.violation()) {
                        case CA_CERTIFICATE -> "Credential issuer leaf certificate must not be a CA";
                        case DIGITAL_SIGNATURE_USAGE_MISSING ->
                            "Credential issuer leaf certificate missing digitalSignature usage";
                    };
            throw new EudiPidTrustException(message, e);
        } catch (VerificationException e) {
            throw new EudiPidTrustException("Credential issuer certificate chain validation failed", e);
        }
    }
}
