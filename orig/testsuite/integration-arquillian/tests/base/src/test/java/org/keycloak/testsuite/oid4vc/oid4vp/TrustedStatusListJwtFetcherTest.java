/*
 * Copyright 2025 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
