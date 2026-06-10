package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql.DcqlCredentialCapabilities;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.keycloak.crypto.Algorithm;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:Ingrid.Kamga@adorsys.com">Ingrid Kamga</a>
 */
public class VerifierDiscoveryServiceTest {

    @Test
    void shouldAdvertiseOnlyDcSdJwtWithDefaultCapabilities() throws Exception {
        VerifierDiscoveryService discoveryService =
                new VerifierDiscoveryService(null, DcqlCredentialCapabilities.createDefault());

        JsonNode metadata = JsonSerialization.mapper.valueToTree(discoveryService.getClientMetadata(null));
        JsonNode vpFormats = metadata.get("vp_formats_supported");
        assertTrue(vpFormats.has("dc+sd-jwt"));
        assertFalse(vpFormats.has("jwt_vc_json"));
    }

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
            // The EC provider in this realm has no certificate,
            // and no access certificate is configured,
            // so self-signed certificates are required.
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
