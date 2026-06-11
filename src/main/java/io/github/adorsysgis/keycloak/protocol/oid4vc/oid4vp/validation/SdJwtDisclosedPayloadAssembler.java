package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_SD;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_SD_HASH_ALGORITHM;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_SD_UNDISCLOSED_ARRAY;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.SdJwtUtils;
import org.keycloak.sdjwt.vp.SdJwtVP;

/**
 * Rebuilds the credential claims tree from an issuer-signed payload and the disclosures presented in an
 * SD-JWT VP (IETF SD-JWT selective disclosure; OpenID4VP §14.9).
 */
final class SdJwtDisclosedPayloadAssembler {

    private static final List<String> RESERVED_CLAIM_NAMES =
            Arrays.asList(CLAIM_NAME_SD, CLAIM_NAME_SD_UNDISCLOSED_ARRAY);

    private SdJwtDisclosedPayloadAssembler() {}

    static ObjectNode assemble(SdJwtVP sdJwt) throws VerificationException {
        return assemble(sdJwt.getIssuerSignedJWT().getPayload(), sdJwt.getDisclosures());
    }

    static ObjectNode assemble(JsonNode issuerPayload, Map<String, String> disclosures) throws VerificationException {
        ObjectNode payload = (ObjectNode) SdJwtUtils.deepClone(issuerPayload);
        discloseRecursively(payload, disclosures);
        return payload;
    }

    private static void discloseRecursively(JsonNode currentNode, Map<String, String> disclosures)
            throws VerificationException {
        if (!currentNode.isObject() && !currentNode.isArray()) {
            return;
        }

        if (currentNode.isObject()) {
            discloseObject((ObjectNode) currentNode, disclosures);
        }

        if (currentNode.isArray()) {
            discloseArray((ArrayNode) currentNode, disclosures);
        }

        for (JsonNode child : currentNode) {
            discloseRecursively(child, disclosures);
        }
    }

    private static void discloseObject(ObjectNode currentObjectNode, Map<String, String> disclosures)
            throws VerificationException {
        JsonNode sdArray = currentObjectNode.get(CLAIM_NAME_SD);
        if (sdArray != null && sdArray.isArray()) {
            for (JsonNode element : sdArray) {
                if (!element.isTextual()) {
                    throw new VerificationException("Unexpected non-string element inside _sd array: " + element);
                }

                String digest = element.asText();
                String disclosure = disclosures.get(digest);
                if (disclosure == null) {
                    continue;
                }

                DecodedDisclosure decoded = decodeObjectDisclosure(disclosure);
                currentObjectNode.set(decoded.claimName(), decoded.claimValue());
            }
        }

        currentObjectNode.remove(CLAIM_NAME_SD);
        currentObjectNode.remove(CLAIM_NAME_SD_HASH_ALGORITHM);
    }

    private static void discloseArray(ArrayNode currentArrayNode, Map<String, String> disclosures)
            throws VerificationException {
        List<Integer> indexesToRemove = new ArrayList<>();

        for (int index = 0; index < currentArrayNode.size(); index++) {
            JsonNode itemNode = currentArrayNode.get(index);
            if (!itemNode.isObject() || itemNode.size() != 1) {
                continue;
            }

            var field = itemNode.properties().iterator().next();
            if (!CLAIM_NAME_SD_UNDISCLOSED_ARRAY.equals(field.getKey())
                    || !field.getValue().isTextual()) {
                continue;
            }

            String digest = field.getValue().asText();
            String disclosure = disclosures.get(digest);
            if (disclosure == null) {
                indexesToRemove.add(index);
                continue;
            }

            DecodedDisclosure decoded = decodeArrayElementDisclosure(disclosure);
            currentArrayNode.set(index, decoded.claimValue());
        }

        indexesToRemove.forEach(currentArrayNode::remove);
    }

    private static DecodedDisclosure decodeObjectDisclosure(String disclosure) throws VerificationException {
        ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
        if (arrayNode.size() != 3) {
            throw new VerificationException("A field disclosure must contain exactly three elements");
        }

        String claimName = arrayNode.get(1).asText();
        if (RESERVED_CLAIM_NAMES.contains(claimName)) {
            throw new VerificationException("Disclosure claim name must not be '_sd' or '...'");
        }

        return new DecodedDisclosure(arrayNode.get(0).asText(), claimName, arrayNode.get(2));
    }

    private static DecodedDisclosure decodeArrayElementDisclosure(String disclosure) throws VerificationException {
        ArrayNode arrayNode = SdJwtUtils.decodeDisclosureString(disclosure);
        if (arrayNode.size() != 2) {
            throw new VerificationException("An array element disclosure must contain exactly two elements");
        }

        return new DecodedDisclosure(arrayNode.get(0).asText(), null, arrayNode.get(1));
    }

    private record DecodedDisclosure(String salt, String claimName, JsonNode claimValue) {}
}
