package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;
import org.keycloak.common.enums.HostnameVerificationPolicy;
import org.keycloak.truststore.TruststoreProvider;

public class StaticTruststoreProvider implements TruststoreProvider {

    private final List<X509Certificate> certs;

    public StaticTruststoreProvider(String... certs) {
        this.certs = Arrays.stream(certs)
                .map(MdocBaseTest::str)
                .map(MdocBaseTest::toCert)
                .toList();
    }

    public StaticTruststoreProvider(X509Certificate... certs) {
        this.certs = Arrays.stream(certs).toList();
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getRootCertificates() {
        return certs.stream().collect(Collectors.groupingBy(X509Certificate::getSubjectX500Principal));
    }

    @Override
    public Map<X500Principal, List<X509Certificate>> getIntermediateCertificates() {
        return Map.of();
    }

    @Override
    public HostnameVerificationPolicy getPolicy() {
        return null;
    }

    @Override
    public SSLSocketFactory getSSLSocketFactory() {
        return null;
    }

    @Override
    public KeyStore getTruststore() {
        return null;
    }

    @Override
    public void close() {}
}
