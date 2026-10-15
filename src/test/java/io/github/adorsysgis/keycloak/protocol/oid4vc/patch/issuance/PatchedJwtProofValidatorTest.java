package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticatorFactory.CREDENTIAL_TYPES_CONFIG_DEFAULT;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance.PatchedJwtProofValidator.ATTR_ALLOW_PROOF_ISS_MISMATCH;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.keycloak.OID4VCConstants.CRYPTOGRAPHIC_BINDING_METHOD_JWK;
import static org.keycloak.models.oid4vci.CredentialScopeModel.VC_BINDING_REQUIRED;
import static org.keycloak.models.oid4vci.CredentialScopeModel.VC_BINDING_REQUIRED_PROOF_TYPES;
import static org.keycloak.models.oid4vci.CredentialScopeModel.VC_CRYPTOGRAPHIC_BINDING_METHODS;
import static org.keycloak.protocol.oid4vc.model.ErrorType.INVALID_PROOF;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.PresentationDuringIssuanceBaseTest;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtProofValidator;
import org.keycloak.protocol.oid4vc.model.CredentialRequest;
import org.keycloak.protocol.oid4vc.model.NonceResponse;
import org.keycloak.protocol.oid4vc.model.ProofType;
import org.keycloak.protocol.oid4vc.model.Proofs;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.util.JsonSerialization;

/**
 * Testing the {@code oid4vci.allow_proof_iss_mismatch} patch in {@code PatchedJwtProofValidator}:
 * a JWT proof whose {@code iss} claim equals the Credential Issuer identifier (instead of the
 * {@code client_id}) is accepted only while the realm attribute is enabled.
 */
class PatchedJwtProofValidatorTest extends PresentationDuringIssuanceBaseTest {

    private static final String CONFIGURATION_ID = PatchedJwtProofValidatorTest.class.getSimpleName();

    @BeforeAll
    static void ensureTestCredentialScope() {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        ensureCredentialScope(realm, CONFIGURATION_ID, CREDENTIAL_TYPES_CONFIG_DEFAULT, null, null);
        enableKeyBinding(realm);
        grantCredentialToTestUser(CONFIGURATION_ID);
    }

    @AfterAll
    static void tearDown() {
        RealmResource realm = keycloak.getKeycloakAdminClient().realm(TEST_REALM_NAME);
        removeCredentialScope(realm, CONFIGURATION_ID);
    }

    private static void enableKeyBinding(RealmResource realm) {
        String scopeId = realm.clientScopes().findAll().stream()
                .filter(candidate -> CONFIGURATION_ID.equals(candidate.getName()))
                .map(ClientScopeRepresentation::getId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Credential scope not found: " + CONFIGURATION_ID));
        ClientScopeResource scopeResource = realm.clientScopes().get(scopeId);
        ClientScopeRepresentation persisted = scopeResource.toRepresentation();
        Map<String, String> attributes =
                new HashMap<>(persisted.getAttributes() == null ? Map.of() : persisted.getAttributes());
        attributes.put(VC_BINDING_REQUIRED, "true");
        attributes.put(VC_BINDING_REQUIRED_PROOF_TYPES, ProofType.JWT);
        attributes.put(VC_CRYPTOGRAPHIC_BINDING_METHODS, CRYPTOGRAPHIC_BINDING_METHOD_JWK);
        persisted.setAttributes(attributes);
        scopeResource.update(persisted);
    }

    @Test
    void acceptsProofWithIssuerMismatchWhenRealmAttributeEnabled() throws Exception {
        withRealmAttributes(Map.of(ATTR_ALLOW_PROOF_ISS_MISMATCH, "true"), () -> {
            HttpResponse response = requestCredentialWithProofIss(getTestRealmEndpoint());
            String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
            assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode(), body);
            assertTrue(JsonSerialization.mapper.readTree(body).has("credentials"), body);
        });
    }

    @Test
    void rejectsProofWithArbitraryIssuerMismatchWhenRealmAttributeEnabled() throws Exception {
        withRealmAttributes(Map.of(ATTR_ALLOW_PROOF_ISS_MISMATCH, "true"), () -> {
            HttpResponse response = requestCredentialWithProofIss("arbitrary-iss");
            OAuth2ErrorRepresentation error = parseErrorResponse(response);

            assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
            assertEquals(INVALID_PROOF.getValue(), error.getError());
            assertTrue(
                    error.getErrorDescription().contains("Issuer claim must be the client_id of the request"),
                    error.getErrorDescription());
        });
    }

    @Test
    void rejectsProofWithIssuerMismatchWhenRealmAttributeDisabled() throws Exception {
        HttpResponse response = requestCredentialWithProofIss(getTestRealmEndpoint());
        OAuth2ErrorRepresentation error = parseErrorResponse(response);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusLine().getStatusCode());
        assertEquals(INVALID_PROOF.getValue(), error.getError());
        assertTrue(
                error.getErrorDescription().contains("Issuer claim must be the client_id of the request"),
                error.getErrorDescription());
    }

    /**
     * Runs a complete pre-authorized credential request whose JWT proof carries {@code iss} equal
     * to the Credential Issuer identifier, and returns the credential-endpoint response.
     */
    private HttpResponse requestCredentialWithProofIss(String proofIssuer) throws Exception {
        JsonNode offer = createCredentialOffer(CONFIGURATION_ID, true);
        String accessToken = requestPreAuthorizedAccessToken(offer);
        String credentialIdentifier = extractCredentialIdentifier(accessToken);
        String cNonce = requestCNonce();
        String proof = buildJwtProof(proofIssuer, getTestRealmEndpoint(), cNonce);
        return requestCredentialWithProof(accessToken, credentialIdentifier, proof);
    }

    private String requestCNonce() throws IOException {
        String nonceUrl = KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/nonce")
                .build()
                .toString();
        HttpPost post = new HttpPost(nonceUrl);
        HttpResponse response = httpClient.execute(post);
        assertEquals(HttpStatus.SC_OK, response.getStatusLine().getStatusCode());
        return parseHttpResponse(response, NonceResponse.class).getNonce();
    }

    private HttpResponse requestCredentialWithProof(String accessToken, String credentialIdentifier, String proofJwt)
            throws IOException {
        CredentialRequest request = new CredentialRequest()
                .setCredentialIdentifier(credentialIdentifier)
                .setProofs(Proofs.create(ProofType.JWT, proofJwt));

        HttpPost post = new HttpPost(KeycloakUriBuilder.fromUri(getTestRealmEndpoint())
                .path("protocol/oid4vc/credential")
                .build()
                .toString());

        post.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);
        post.setEntity(new StringEntity(JsonSerialization.valueAsString(request), ContentType.APPLICATION_JSON));
        return httpClient.execute(post);
    }

    /**
     * Builds a signed {@code openid4vci-proof+jwt} with the given {@code iss}, {@code aud}, and nonce.
     */
    private static String buildJwtProof(String proofIssuer, String aud, String nonce) throws Exception {
        JWK holderKey = SdJwtVPTestUtils.getUserJwk();
        KeyWrapper keyWrapper = ECTestUtils.getEcKeyWrapper(holderKey);
        keyWrapper.setKid(null);
        JWK publicJwk = ECTestUtils.getECPublicJwk(holderKey);
        publicJwk.setAlgorithm(Algorithm.ES256);

        AccessToken token = new AccessToken();
        token.addAudience(aud);
        token.setNonce(nonce);
        token.issuer(proofIssuer);
        token.issuedNow();

        return new JWSBuilder()
                .type(JwtProofValidator.PROOF_JWT_TYP)
                .jwk(publicJwk)
                .jsonContent(token)
                .sign(new ECDSASignatureSignerContext(keyWrapper));
    }
}
