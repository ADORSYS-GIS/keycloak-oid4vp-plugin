package de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.adorsys.gis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class VerifierDiscoveryServiceTest {

    @Nested
    class TestPreferECKey extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            return TEST_REALM_NAME;
        }

        @Test
        public void shoudPreferECKey() throws Exception {
            // Retrieve an authorization request
            AuthorizationContext authContext = requestAuthorizationRequest();
            String authRequest = authContext.getAuthorizationRequest();
            String signedRequestJwt = resolveSignedRequestObject(authRequest);

            // Assert signing algorithm is ES256
            assertEquals(Algorithm.ES256, parseSigningAlgorithm(signedRequestJwt));
        }
    }

    @Nested
    class TestDefaultToRSAKey extends OID4VPBaseKeycloakTest {

        @Override
        public String getActiveTestRealm() {
            // The EC provider in this realm has no certificate
            return TEST_REALM_V2_NAME;
        }

        @Test
        public void shoudDefaultToRSAKeyIfNoECKeyWithCertificate() throws Exception {
            // Retrieve an authorization request
            AuthorizationContext authContext = requestAuthorizationRequest();
            String authRequest = authContext.getAuthorizationRequest();
            String signedRequestJwt = resolveSignedRequestObject(authRequest);

            // Assert signing algorithm defaults to RS256
            assertEquals(Algorithm.RS256, parseSigningAlgorithm(signedRequestJwt));
        }
    }

    private static String parseSigningAlgorithm(String jwt) throws Exception {
        JWSInput jwsInput = new JWSInput(jwt);
        JWSHeader jwsHeader = jwsInput.getHeader();
        return jwsHeader.getAlgorithm().name();
    }
}
