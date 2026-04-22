package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import java.util.List;
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

            // Assert the configured RSA access certificate is advertised
            assertEquals(List.of(getConfiguredAccessCertificate()), parseX5c(signedRequestJwt));
        }

        private String getConfiguredAccessCertificate() {
            ObjectNode json = getTestResourceJson("/realms/test-realm-v2.json");
            ArrayNode config = (ArrayNode) json.get("authenticatorConfig");
            return config.get(0).get("config").get("accessCertificate").asText();
        }
    }

    private static String parseSigningAlgorithm(String jwt) throws Exception {
        JWSInput jwsInput = new JWSInput(jwt);
        JWSHeader jwsHeader = jwsInput.getHeader();
        return jwsHeader.getAlgorithm().name();
    }

    private static List<String> parseX5c(String jwt) throws Exception {
        JWSInput jwsInput = new JWSInput(jwt);
        JWSHeader jwsHeader = jwsInput.getHeader();
        return jwsHeader.getX5c();
    }
}
