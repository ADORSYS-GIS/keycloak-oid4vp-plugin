package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import org.keycloak.common.util.Base64Url;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;

public class X509HashUtils {

    // Private constructor to prevent instantiation
    private X509HashUtils() {}

    /**
     * Compute the x509_hash for the provided X.509 certificate.
     * <p></p>
     * The resulting string matches the x509_hash value required when a client's
     * identifier uses the "x509_hash" prefix.
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-defined-client-identifier-p">Defined Client Identifier Prefixes</a>
     */
    public static String computeX509Hash(X509Certificate cert) {
        try {
            byte[] encoded = Objects.requireNonNull(cert).getEncoded();
            byte[] hashedOutput = HashUtils.hash(JavaAlgorithm.SHA256, encoded);
            return Base64Url.encode(hashedOutput);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Error computing X509 hash of argument certificate", e);
        }
    }
}
