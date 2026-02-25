package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.stub.CustomSdJwtAuthenticatorFactory.MockTrustedStatusListJwtFetcher;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureProvider;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.models.KeycloakSession;
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
    void before() {
        Mockito.lenient()
                .when(session.getProvider(SignatureProvider.class, Algorithm.ES256))
                .thenReturn(new ECDSASignatureProvider(session, Algorithm.ES256));
        fetcher = new MockTrustedStatusListJwtFetcher(session);
    }

    @Test
    public void shouldAcceptTrustedStatusListJwts() {
        String uri = "https://example.com/status-list-jwt";
        assertDoesNotThrow(() -> fetcher.fetchStatusListJwt(uri));
    }

    @Test
    public void shouldRejectNonHttpsURIs() {
        String uri = "http://example.com/status-list-jwt";
        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertTrue(e.getMessage().startsWith("Status list JWT URI must use HTTPS:"));
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_InvalidSignature() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+invalid-signature",
                "Error during JWS signature verification",
                "Invalid JWS signature");
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_NoX5C() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+no-x5c",
                "Could not extract verifier from X5C certificate chain",
                "Missing or empty x5c header in JWS");
    }

    private void shouldRejectInvalidStatusListJwt(
            String testVector, String expectedErrorMessage, String expectedCauseMessage) {
        String uri = "https://example.com/" + testVector;
        var e = assertThrows(ReferencedTokenValidationException.class, () -> fetcher.fetchStatusListJwt(uri));
        assertEquals(expectedErrorMessage, e.getMessage());
        assertEquals(expectedCauseMessage, e.getCause().getMessage());
    }
}
