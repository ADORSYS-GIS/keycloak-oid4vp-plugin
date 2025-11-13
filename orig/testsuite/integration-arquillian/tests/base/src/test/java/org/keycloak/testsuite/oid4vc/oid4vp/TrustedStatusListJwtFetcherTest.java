package org.keycloak.testsuite.oid4vc.oid4vp;

import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.protocol.oid4vc.tokenstatus.http.TrustedStatusListJwtFetcher;
import org.keycloak.testsuite.oid4vc.issuance.signing.OID4VCIssuerEndpointTest;
import org.keycloak.testsuite.oid4vp.CustomSdJwtAuthenticatorFactory;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test trust enforcement of retrieved status list JWTs.
 *
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class TrustedStatusListJwtFetcherTest extends OID4VCIssuerEndpointTest {

    @Test
    public void shouldAcceptTrustedStatusListJwts() {
        String uri = "https://example.com/status-list-jwt";
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                mockFetcher(session).fetchStatusListJwt(uri);
            } catch (Exception e) {
                fail("Operation should not fail");
            }
        });
    }

    @Test
    public void shouldRejectNonHttpsURIs() {
        String uri = "http://example.com/status-list-jwt";
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                mockFetcher(session).fetchStatusListJwt(uri);
                fail("Operation should fail");
            } catch (Exception e) {
                assertTrue(e.getMessage().startsWith("Status list JWT URI must use HTTPS:"));
            }
        });
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_InvalidSignature() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+invalid-signature",
                "Error during JWS signature verification",
                "Invalid JWS signature"
        );
    }

    @Test
    public void shouldRejectInvalidStatusListJwts_NoX5C() {
        shouldRejectInvalidStatusListJwt(
                "status-list-jwt+no-x5c",
                "Could not extract verifier from X5C certificate chain",
                "Missing or empty x5c header in JWS"
        );
    }

    private void shouldRejectInvalidStatusListJwt(
            String testVector,
            String expectedErrorMessage,
            String expectedCauseMessage
    ) {
        String uri = "https://example.com/" + testVector;
        testingClient.server(TEST_REALM_NAME).run(session -> {
            try {
                mockFetcher(session).fetchStatusListJwt(uri);
                fail("Operation should fail");
            } catch (Exception e) {
                assertEquals(expectedErrorMessage, e.getMessage());
                assertEquals(expectedCauseMessage, e.getCause().getMessage());
            }
        });
    }

    static TrustedStatusListJwtFetcher mockFetcher(KeycloakSession session) {
        return new CustomSdJwtAuthenticatorFactory.MockTrustedStatusListJwtFetcher(session);
    }
}
