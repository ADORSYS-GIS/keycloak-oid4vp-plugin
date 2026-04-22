package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.PemUtils;

class X509HashUtilsTest {

    @BeforeAll
    static void setup() {
        CryptoIntegration.init(X509HashUtilsTest.class.getClassLoader());
    }

    @Test
    void computeX509Hash_returnsExpectedBase64Url() {
        // Test vector taken from AnimoID playground (https://playground.animo.id)
        String testCertificate = """
                MIIB7zCCAZWgAwIBAgIQJ31AWMJSWLqPziKmUdhBQTAKBggqhkjOPQQDAjAdMQ4w
                DAYDVQQDEwVBbmltbzELMAkGA1UEBhMCTkwwHhcNMjUxMTA4MTYyODMwWhcNMjYx
                MTI4MTYyODMwWjAhMRIwEAYDVQQDEwljcmVkbyBkY3MxCzAJBgNVBAYTAk5MMFkw
                EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ1OElTvxJHJBhylt/6Lt44eUYsLyAClF
                eh/+8NxXMglBydMb/znOK0+G3xG311HZbU7LNoA/aPnSKyV42yV/gKOBsjCBrzAd
                BgNVHQ4EFgQUxj/gBS23ctm7nogxNpB+YZI6UzswDgYDVR0PAQH/BAQDAgeAMBUG
                A1UdJQEB/wQLMAkGByiBjF0FAQIwHwYDVR0jBBgwFoAUVC5XW1PTYNo6yWnkJGgv
                BVCtWZUwJgYDVR0SBB8wHYYbaHR0cHM6Ly9wbGF5Z3JvdW5kLmFuaW1vLmlkMB4G
                A1UdEQQXMBWCE3BsYXlncm91bmQuYW5pbW8uaWQwCgYIKoZIzj0EAwIDSAAwRQIg
                L5EGUhzhwL+7IlYJTgy3h+ruhnhyGv25JXJtuwL6TlUCIQCFasWt8IswxpQxBlr7
                R7MuldfafDHtip7G5ApLM11LdQ==
            """;

        X509Certificate cert = PemUtils.decodeCertificate(testCertificate);
        String actual = X509HashUtils.computeX509Hash(cert);
        assertEquals("3jLUkxFqNN3_h2OUSoMqfbZpsg99YwjMPKVeu2PDhoc", actual);
    }
}
