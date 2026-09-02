package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocBaseTest;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.Executors;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.testcontainers.Testcontainers;

/**
 * Process-local HTTPS fixture serving a cryptographically signed two-provider PID LoTE.
 *
 * <p>The Keycloak integration-test container reaches this server through Testcontainers' host-port
 * forwarding. Its TLS certificate is added to a temporary copy of the normal test truststore, so
 * the production {@link org.keycloak.broker.provider.util.SimpleHttp} path is exercised without
 * disabling TLS validation.
 */
public final class EudiPidTrustListTestServer {

    public static final String PROVIDER_A_ID = "PID-PROVIDER-A";
    public static final String PROVIDER_B_ID = "PID-PROVIDER-B";
    private static final char[] STORE_PASSWORD = "password".toCharArray();
    private static final String PATH = "/pid-provider.jwt";

    private final HttpsServer server;
    private final Path keycloakTruststore;
    private volatile String trustListJwt;

    private EudiPidTrustListTestServer(HttpsServer server, Path keycloakTruststore) {
        this.server = server;
        this.keycloakTruststore = keycloakTruststore;
    }

    public static EudiPidTrustListTestServer start(Path sourceTruststore) {
        try {
            X509Certificate tlsCertificate = MdocBaseTest.getIssuerCertRef1();
            SSLContext sslContext = serverSslContext(tlsCertificate);

            HttpsServer server = HttpsServer.create(new InetSocketAddress(0), 0);
            EudiPidTrustListTestServer fixture =
                    new EudiPidTrustListTestServer(server, augmentedTruststore(sourceTruststore, tlsCertificate));
            server.setHttpsConfigurator(new HttpsConfigurator(sslContext));
            server.setExecutor(Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "eudi-pid-trust-list-test-server");
                thread.setDaemon(true);
                return thread;
            }));
            server.createContext(PATH, exchange -> {
                String body = fixture.trustListJwt;
                if (body == null) {
                    exchange.sendResponseHeaders(503, -1);
                    exchange.close();
                    return;
                }

                byte[] response = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/trustlist+jwt");
                exchange.sendResponseHeaders(200, response.length);
                try (OutputStream output = exchange.getResponseBody()) {
                    output.write(response);
                }
            });
            server.start();
            Testcontainers.exposeHostPorts(server.getAddress().getPort());
            return fixture;
        } catch (Exception e) {
            throw new IllegalStateException("Could not start EUDI PID trust-list test server", e);
        }
    }

    public String urlFromKeycloakContainer() {
        return "https://host.testcontainers.internal:" + server.getAddress().getPort() + PATH;
    }

    public Path keycloakTruststore() {
        return keycloakTruststore;
    }

    /** Installs a fresh, valid LoTE containing two distinct provider/certificate associations. */
    public void serveSignedTrustList() {
        try {
            X509Certificate signingCertificate = MdocBaseTest.getIssuerCertRef1();
            String payload = """
                    {
                      "LoTE": {
                        "ListAndSchemeInformation": {
                          "LoTEType": "%s",
                          "ListIssueDateTime": "%s",
                          "NextUpdate": "%s"
                        },
                        "TrustedEntitiesList": [
                          %s,
                          %s
                        ]
                      }
                    }
                    """.formatted(
                            EudiPidTrustListProvider.PID_PROVIDERS_LOTE_TYPE,
                            Instant.now().minusSeconds(60),
                            Instant.now().plusSeconds(3600),
                            provider(PROVIDER_A_ID, MdocBaseTest.getIssuerCertRef1()),
                            provider(PROVIDER_B_ID, MdocBaseTest.getIssuerCertRef2()));

            KeyWrapper signingKey = new KeyWrapper();
            signingKey.setPrivateKey(MdocBaseTest.getIssuerKeyRef1().toECPrivateKey());
            signingKey.setPublicKey(signingCertificate.getPublicKey());
            signingKey.setAlgorithm(Algorithm.ES256);
            signingKey.setType(KeyType.EC);
            signingKey.setUse(KeyUse.SIG);

            trustListJwt = new JWSBuilder()
                    .type("trustlist+jwt")
                    .x5c(List.of(signingCertificate))
                    .content(payload.getBytes(StandardCharsets.UTF_8))
                    .sign(new ECDSASignatureSignerContext(signingKey));
        } catch (Exception e) {
            throw new IllegalStateException("Could not build signed EUDI PID trust list", e);
        }
    }

    private static String provider(String providerId, X509Certificate certificate) throws Exception {
        String encodedCertificate = java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());
        return """
                {
                  "TrustedEntityInformation": {
                    "TEName": [{ "lang": "en", "value": "%s" }],
                    "TETradeName": [{ "lang": "en", "value": "%s" }]
                  },
                  "TrustedEntityServices": [
                    {
                      "ServiceInformation": {
                        "ServiceTypeIdentifier": "%s",
                        "ServiceName": [{ "lang": "en", "value": "PID issuance" }],
                        "ServiceDigitalIdentity": {
                          "X509Certificates": [{ "val": "%s" }]
                        }
                      }
                    }
                  ]
                }
                """.formatted(
                        providerId, providerId, EudiPidTrustListProvider.PID_ISSUANCE_SERVICE_TYPE, encodedCertificate);
    }

    private static SSLContext serverSslContext(X509Certificate certificate) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, STORE_PASSWORD);
        keyStore.setKeyEntry(
                "server",
                MdocBaseTest.getIssuerKeyRef1().toECPrivateKey(),
                STORE_PASSWORD,
                new java.security.cert.Certificate[] {certificate});

        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, STORE_PASSWORD);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagers.getKeyManagers(), null, new SecureRandom());
        return sslContext;
    }

    private static Path augmentedTruststore(Path sourceTruststore, X509Certificate serverCertificate) throws Exception {
        KeyStore truststore = KeyStore.getInstance("JKS");
        try (var input = Files.newInputStream(sourceTruststore)) {
            truststore.load(input, STORE_PASSWORD);
        }
        truststore.setCertificateEntry("eudi-pid-trust-list-test-server", serverCertificate);

        Path target = Files.createTempFile("keycloak-test-truststore-", ".jks");
        target.toFile().deleteOnExit();
        try (var output = Files.newOutputStream(target)) {
            truststore.store(output, STORE_PASSWORD);
        }
        Files.setPosixFilePermissions(
                target,
                EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE,
                        PosixFilePermission.GROUP_READ,
                        PosixFilePermission.OTHERS_READ));
        return target;
    }
}
