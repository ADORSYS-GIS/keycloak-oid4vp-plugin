package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.sdjwt.DisclosureSpec;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

class SdJwtClaimReaderTest {

    private static final String HASH_ALG = "sha-256";
    private static SignatureSignerContext ISSUER_SIGNER;

    @BeforeAll
    static void initCrypto() throws Exception {
        CryptoIntegration.init(SdJwtClaimReaderTest.class.getClassLoader());
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        ISSUER_SIGNER = new AsymmetricSignatureSignerContext(RSATestUtils.getRsaKeyWrapper(issuerJwk));
    }

    @Test
    void resolvesNestedObjectDisclosure() throws Exception {
        String streetDisclosure =
                objectDisclosure("street-salt", "street", JsonNodeFactory.instance.textNode("42 Market Street"));
        String digest = digest(streetDisclosure);

        ObjectNode issuerPayload = JsonNodeFactory.instance.objectNode();
        issuerPayload.put("vct", "https://example.com/vct");
        ObjectNode address = issuerPayload.putObject("address");
        address.put("country", "DE");
        address.putArray("_sd").add(digest);

        ObjectNode disclosed = SdJwtDisclosedPayloadAssembler.assemble(issuerPayload, Map.of(digest, streetDisclosure));
        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(disclosed, List.of("address", "street"));

        assertEquals(1, resolved.size());
        assertEquals("42 Market Street", resolved.getFirst().asText());
    }

    @Test
    void resolvesArrayElementDisclosure() throws Exception {
        String elementDisclosure = arrayElementDisclosure("scores-salt", JsonNodeFactory.instance.numberNode(20));
        String digest = digest(elementDisclosure);

        ObjectNode issuerPayload = JsonNodeFactory.instance.objectNode();
        issuerPayload.put("vct", "https://example.com/vct");
        ArrayNode scores = issuerPayload.putArray("scores");
        scores.add(10);
        ObjectNode placeholder = scores.addObject();
        placeholder.put("...", digest);

        ObjectNode disclosed =
                SdJwtDisclosedPayloadAssembler.assemble(issuerPayload, Map.of(digest, elementDisclosure));
        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(disclosed, List.of("scores", 1));

        assertEquals(1, resolved.size());
        assertEquals(20, resolved.getFirst().asInt());
    }

    @Test
    void resolvesUndisclosedClaimFromSdJwtPresentation() throws Exception {
        ObjectNode claimSet = JsonNodeFactory.instance.objectNode();
        claimSet.put("vct", "https://example.com/vct");
        claimSet.put("exp", Time.currentTime() + 300);
        claimSet.put("given_name", "Alice");

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedClaim("given_name", "given-name-salt")
                .build();

        IssuerSignedJWT issuerSignedJwt =
                IssuerSignedJWT.builder().withClaims(claimSet, disclosureSpec).build();

        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJwt)
                .withIssuerSigningContext(ISSUER_SIGNER)
                .build()
                .toSdJwtString();

        SdJwtVP presentation = SdJwtVP.of(sdJwt);

        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(presentation, List.of("given_name"));

        assertEquals(1, resolved.size());
        assertEquals("Alice", resolved.getFirst().asText());
    }

    @Test
    void resolvesUndisclosedArrayElementFromSdJwtPresentation() throws Exception {
        ObjectNode claimSet = JsonNodeFactory.instance.objectNode();
        claimSet.put("vct", "https://example.com/vct");
        claimSet.put("exp", Time.currentTime() + 300);
        ArrayNode scores = claimSet.putArray("scores");
        scores.add(10);
        scores.add(20);

        DisclosureSpec disclosureSpec = DisclosureSpec.builder()
                .withUndisclosedArrayElt("scores", 1, "scores-element-salt")
                .build();

        IssuerSignedJWT issuerSignedJwt =
                IssuerSignedJWT.builder().withClaims(claimSet, disclosureSpec).build();

        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(issuerSignedJwt)
                .withIssuerSigningContext(ISSUER_SIGNER)
                .build()
                .toSdJwtString();

        SdJwtVP presentation = SdJwtVP.of(sdJwt);

        List<JsonNode> resolved = SdJwtClaimReader.resolveClaimPath(presentation, List.of("scores", 1));

        assertEquals(1, resolved.size());
        assertEquals(20, resolved.getFirst().asInt());
    }

    private static String objectDisclosure(String salt, String claimName, JsonNode claimValue)
            throws JsonProcessingException {
        return SdJwtUtils.encodeNoPad(SdJwtUtils.printJsonArray(new Object[] {salt, claimName, claimValue}));
    }

    private static String arrayElementDisclosure(String salt, JsonNode claimValue) throws JsonProcessingException {
        return SdJwtUtils.encodeNoPad(SdJwtUtils.printJsonArray(new Object[] {salt, claimValue}));
    }

    private static String digest(String disclosure) {
        return SdJwtUtils.hashAndBase64EncodeNoPad(disclosure, HASH_ALG);
    }
}
