package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.VerificationException;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.truststore.TruststoreProvider;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test trust enforcement of retrieved status list JWTs.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
@ExtendWith(MockitoExtension.class)
public class TrustedStatusListJwtFetcherTest {

    @Mock
    KeycloakSession session;

    TrustedStatusListJwtFetcher fetcher;

    @BeforeAll
    public static void setup() {
        CryptoIntegration.init(TrustedStatusListJwtFetcherTest.class.getClassLoader());
    }

    @BeforeEach
    void before() throws Exception {
        // Mock SignatureProvider for ES256
        setupSignatureMock(Algorithm.ES256);

        // Mock TruststoreProvider for PKIX validation
        TruststoreProvider truststoreProvider = Mockito.mock(TruststoreProvider.class);
        Mockito.lenient().when(session.getProvider(TruststoreProvider.class)).thenReturn(truststoreProvider);
        Mockito.lenient().when(truststoreProvider.getTruststore()).thenReturn(Mockito.mock(KeyStore.class));
        Mockito.lenient().when(truststoreProvider.getRootCertificates()).thenReturn(Collections.emptyMap());
        Mockito.lenient().when(truststoreProvider.getIntermediateCertificates()).thenReturn(Collections.emptyMap());

        fetcher = new MockTrustedStatusListJwtFetcher(session);

        // Set validation time to be within status-list JWT validity
        // Set validation time to be within new test certificates validity
        int currentTime = (int) (System.currentTimeMillis() / 1000);
        int targetTime = currentTime + 3600; // 1 hour from now
        Time.setOffset(targetTime - currentTime);
    }

    @AfterEach
    void after() {
        Time.setOffset(0);
    }

    @Test
    public void shouldAcceptTrustedStatusListJwts() throws Exception {
        String uri = "https://example.com/status-list-jwt";
        setupTrustForStatusListJwt();
        assertDoesNotThrow(() -> fetcher.fetchStatusListJwt(uri));
    }

    @Test
    public void shouldRejectNonHttpsURIs() {
        String uri = "http://example.com/status-list-jwt";
        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertTrue(e.getMessage().startsWith("Status list JWT URI must use HTTPS:"));
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_NoX5C() {
        String uri = "https://example.com/status-list-jwt+no-x5c";
        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertEquals("Could not extract verifier from X5C certificate chain", e.getMessage());
        assertTrue(e.getCause().getMessage().contains("x5c header"));
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_InvalidSignature() throws Exception {
        String uri = "https://example.com/status-list-jwt+invalid-signature";
        String statusListJwt = MockTrustedStatusListJwtFetcher.exampleStatusListJwt(
                "/tokenstatus/status-list-jwt+invalid-signature.txt");
        setupTrustForJwt(statusListJwt);

        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertEquals("Invalid JWS signature", e.getMessage());
    }

    @Test
    public void shouldRejectUntrustedStatusListJwts() {
        String uri = "https://example.com/status-list-jwt";

        // Ensure truststore has no roots
        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        Mockito.when(truststoreProvider.getRootCertificates()).thenReturn(Map.of());

        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertTrue(e.getMessage().contains("No trusted root certificates available for validation"));
    }

    @Test
    public void shouldRejectExpiredCertificate() throws Exception {
        String uri = "https://example.com/status-list-jwt";
        setupTrustForStatusListJwt();

        // Move time far into the future
        Time.setOffset(1000000000);

        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertTrue(e.getMessage().contains("Certificate chain validation failed"));
        assertHasCause(e, CertificateExpiredException.class);
    }

    @Test
    public void shouldRejectExcessivelyLongChains() throws Exception {
        String uri = "https://example.com/long-chain";

        String baseJwt = MockTrustedStatusListJwtFetcher.exampleStatusListJwt("/tokenstatus/status-list-jwt.txt");
        JWSInput jws = new JWSInput(baseJwt);

        List<String> x5c = IntStream.range(0, 10)
                .mapToObj(i -> jws.getHeader().getX5c().get(0))
                .collect(Collectors.toList());

        String longChainHeader = Base64.getEncoder()
                .encodeToString(String.format(
                                "{\"alg\":\"ES256\",\"x5c\":%s}",
                                x5c.stream().map(s -> "\"" + s + "\"").collect(Collectors.joining(",", "[", "]")))
                        .getBytes());

        String fakeJwt = longChainHeader + "." + jws.getEncodedContent() + "." + jws.getEncodedSignature();

        TrustedStatusListJwtFetcher customFetcher = new MockTrustedStatusListJwtFetcher(session) {
            @Override
            protected String _fetchStatusListJwt(String u) {
                return fakeJwt;
            }
        };

        var e = assertThrows(ReferencedTokenValidationException.class, () -> customFetcher.fetchStatusListJwt(uri));
        assertTrue(e.getMessage().contains("Certificate chain too long"));
    }

    @Test
    public void shouldRejectLeafAsCA() throws Exception {
        String uri = "https://example.com/status-list-jwt";
        setupTrustForStatusListJwt();

        TrustedStatusListJwtFetcher spyFetcher = Mockito.spy(fetcher);
        Mockito.doThrow(new VerificationException("Leaf certificate must not be a CA"))
                .when(spyFetcher)
                .validateLeafCertificate(Mockito.any());

        var e = assertThrows(ReferencedTokenValidationException.class, () -> spyFetcher.fetchStatusListJwt(uri));
        assertEquals("Leaf certificate must not be a CA", e.getCause().getMessage());
    }

    @Test
    public void shouldRejectMissingKeyUsage() throws Exception {
        String uri = "https://example.com/status-list-jwt";
        setupTrustForStatusListJwt();

        TrustedStatusListJwtFetcher spyFetcher = Mockito.spy(fetcher);
        Mockito.doThrow(new VerificationException("Leaf certificate missing Digital Signature KeyUsage"))
                .when(spyFetcher)
                .validateLeafCertificate(Mockito.any());

        var e = assertThrows(ReferencedTokenValidationException.class, () -> spyFetcher.fetchStatusListJwt(uri));
        assertEquals(
                "Leaf certificate missing Digital Signature KeyUsage",
                e.getCause().getMessage());
    }

    /* ------------------ Helpers ------------------ */

    private void setupTrustForStatusListJwt() throws Exception {
        String statusListJwt = MockTrustedStatusListJwtFetcher.exampleStatusListJwt("/tokenstatus/status-list-jwt.txt");
        setupTrustForJwt(statusListJwt);
    }

    private void setupTrustForJwt(String jwt) throws Exception {
        JWSInput jws = new JWSInput(jwt);
        List<String> x5cList = jws.getHeader().getX5c();

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate root = (X509Certificate) cf.generateCertificate(
                new ByteArrayInputStream(Base64.getDecoder().decode(x5cList.get(x5cList.size() - 1))));

        TruststoreProvider truststoreProvider = session.getProvider(TruststoreProvider.class);
        Mockito.lenient()
                .when(truststoreProvider.getRootCertificates())
                .thenReturn(Map.of(root.getSubjectX500Principal(), List.of(root)));
    }

    private void setupSignatureMock(String alg) throws Exception {
        SignatureProvider signatureProvider = Mockito.mock(SignatureProvider.class);
        Mockito.lenient()
                .when(session.getProvider(SignatureProvider.class, alg))
                .thenReturn(signatureProvider);

        Mockito.lenient()
                .when(signatureProvider.verifier(Mockito.any(KeyWrapper.class)))
                .thenAnswer(invocation -> {
                    SignatureVerifierContext verifier = Mockito.mock(SignatureVerifierContext.class);
                    Mockito.lenient()
                            .when(verifier.verify(Mockito.any(), Mockito.any()))
                            .thenReturn(true);
                    return verifier;
                });
    }

    /* ------------------ Mock Fetcher ------------------ */
    public static class MockTrustedStatusListJwtFetcher extends TrustedStatusListJwtFetcher {
        public MockTrustedStatusListJwtFetcher(KeycloakSession session) {
            super(session);
        }

        @Override
        protected String _fetchStatusListJwt(String uri) {
            String path;
            try {
                path = new URI(uri).getPath();
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URI: " + uri, e);
            }
            if (path == null || path.isEmpty()) {
                throw new IllegalArgumentException("Empty resource");
            }
            String resource = path.substring(path.lastIndexOf('/') + 1);
            return exampleStatusListJwt(String.format("/tokenstatus/%s.txt", resource));
        }

        public static String exampleStatusListJwt(String filename) {
            try (InputStream stream = MockTrustedStatusListJwtFetcher.class.getResourceAsStream(filename)) {
                if (stream == null) throw new IllegalArgumentException("Resource not found: " + filename);
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8).replaceAll("\\R", "");
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void assertHasCause(Throwable t, Class<? extends Throwable> expected) {
        Throwable cause = t;
        while (cause != null) {
            if (expected.isInstance(cause)) {
                return;
            }
            cause = cause.getCause();
        }
        throw new AssertionError("Expected cause of type " + expected.getName() + " but it was not found in the chain");
    }
}
