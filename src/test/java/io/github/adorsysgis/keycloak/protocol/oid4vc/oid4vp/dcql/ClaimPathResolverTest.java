package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.util.JsonSerialization;

class ClaimPathResolverTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(ClaimPathResolverTest.class.getClassLoader());
    }

    @Test
    void resolveInJsonReturnsValueForNestedObjectPath() {
        ObjectNode root = JsonSerialization.mapper.createObjectNode();
        ObjectNode address = root.putObject("address");
        address.put("street_address", "123 Main St");

        List<JsonNode> resolved = ClaimPathResolver.resolveInJson(root, List.of("address", "street_address"));

        assertEquals(1, resolved.size());
        assertEquals("123 Main St", resolved.getFirst().asText());
    }

    @Test
    void resolveInJsonReturnsEmptyForMissingPath() {
        ObjectNode root = JsonSerialization.mapper.createObjectNode();
        root.put("given_name", "Alice");

        assertTrue(ClaimPathResolver.resolveInJson(root, List.of("family_name")).isEmpty());
    }

    @Test
    void resolveInJsonReturnsEmptyForEmptyPath() {
        ObjectNode root = JsonSerialization.mapper.createObjectNode();
        root.put("given_name", "Alice");

        assertTrue(ClaimPathResolver.resolveInJson(root, List.of()).isEmpty());
    }

    @Test
    void resolveInJsonReturnsEmptyWhenPathTraversesNonObjectValue() {
        ObjectNode root = JsonSerialization.mapper.createObjectNode();
        root.put("age", 21);

        assertTrue(
                ClaimPathResolver.resolveInJson(root, List.of("age", "years")).isEmpty());
    }

    @Test
    void resolveInJsonReturnsEmptyForNullRoot() {
        assertTrue(ClaimPathResolver.resolveInJson(null, List.of("given_name")).isEmpty());
    }

    @Test
    void resolveInSdJwtReturnsIssuerSignedClaim() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        List<JsonNode> resolved = ClaimPathResolver.resolveInSdJwt(sdJwt, List.of("given_name"));

        assertEquals(1, resolved.size());
        assertEquals("Alice", resolved.getFirst().asText());
    }

    @Test
    void resolveInSdJwtReturnsNestedPathThroughDisclosedClaim() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> {
                    ObjectNode address = claimSet.putObject("address");
                    address.put("street_address", "123 Main St");
                },
                DisclosureSpec.builder()
                        .withUndisclosedClaim("address", "address-salt")
                        .build());

        List<JsonNode> resolved = ClaimPathResolver.resolveInSdJwt(sdJwt, List.of("address", "street_address"));

        assertEquals(1, resolved.size());
        assertEquals("123 Main St", resolved.getFirst().asText());
    }

    @Test
    void resolveInSdJwtReturnsEmptyForNullPath() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        assertTrue(ClaimPathResolver.resolveInSdJwt(sdJwt, null).isEmpty());
    }

    @Test
    void resolveInSdJwtReturnsSingleDisclosedClaim() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder()
                        .withUndisclosedClaim("given_name", "given-name-salt")
                        .build());

        List<JsonNode> resolved = ClaimPathResolver.resolveInSdJwt(sdJwt, List.of("given_name"));

        assertEquals(1, resolved.size());
        assertEquals("Alice", resolved.getFirst().asText());
    }

    @Test
    void resolveInSdJwtReturnsEmptyForMissingClaim() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> claimSet.put("given_name", "Alice"),
                DisclosureSpec.builder().build());

        assertTrue(
                ClaimPathResolver.resolveInSdJwt(sdJwt, List.of("family_name")).isEmpty());
    }

    @Test
    void resolveInSdJwtReturnsEmptyForMissingNestedPathInDisclosedClaim() throws Exception {
        SdJwtVP sdJwt = sdJwtVp(
                claimSet -> {
                    ObjectNode address = claimSet.putObject("address");
                    address.put("street_address", "123 Main St");
                },
                DisclosureSpec.builder()
                        .withUndisclosedClaim("address", "address-salt")
                        .build());

        assertTrue(ClaimPathResolver.resolveInSdJwt(sdJwt, List.of("address", "postal_code"))
                .isEmpty());
    }

    private static SdJwtVP sdJwtVp(Consumer<ObjectNode> claimCustomizer, DisclosureSpec disclosureSpec)
            throws Exception {
        ObjectNode claimSet = JsonSerialization.mapper.createObjectNode();
        claimSet.put("iss", "https://example.com/realms/test");
        claimSet.put("vct", VCT);
        claimSet.put("sub", "user-id");
        claimCustomizer.accept(claimSet);

        IssuerSignedJWT issuerSignedJWT =
                IssuerSignedJWT.builder().withClaims(claimSet, disclosureSpec).build();

        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        String token = SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJWT)
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();
        return SdJwtVP.of(token);
    }
}
