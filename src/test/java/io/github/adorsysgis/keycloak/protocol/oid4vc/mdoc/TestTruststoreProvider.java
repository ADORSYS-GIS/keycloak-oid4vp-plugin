package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.StaticTruststoreProvider;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class TestTruststoreProvider extends StaticTruststoreProvider {

    public TestTruststoreProvider(String... certs) {
        super(Arrays.stream(certs)
                .map(MdocBaseTest::str)
                .map(MdocBaseTest::toCert)
                .toList());
    }

    public TestTruststoreProvider(X509Certificate... certs) {
        super(Arrays.asList(certs));
    }
}
