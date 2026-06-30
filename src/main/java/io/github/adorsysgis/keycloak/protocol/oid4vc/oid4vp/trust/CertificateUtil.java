package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

final class CertificateUtil {

    private CertificateUtil() {}

    static X509Certificate parseCertificate(String base64OrPem) throws CertificateException {
        String normalized = base64OrPem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(normalized);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
    }

    static String sha256Fingerprint(X509Certificate certificate) {
        try {
            return HexFormat.of().formatHex(HashUtils.hash(JavaAlgorithm.SHA256, certificate.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("Could not calculate certificate fingerprint", e);
        }
    }
}
