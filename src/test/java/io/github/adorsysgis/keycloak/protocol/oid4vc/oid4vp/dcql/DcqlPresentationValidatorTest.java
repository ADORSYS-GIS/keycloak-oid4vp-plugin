package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.common.VerificationException;

class DcqlPresentationValidatorTest {

    private final JwtVcJsonCredentialConstrainer jwtVcConstrainer = new JwtVcJsonCredentialConstrainer();

    @Test
    void acceptsJwtVcJsonPresentationMatchingTypeValuesAndClaims() {
        String vcJwt = unsignedJwt("""
                {
                  "type": ["VerifiableCredential", "IDCredential"],
                  "credentialSubject": {
                    "given_name": "Max",
                    "family_name": "Mustermann"
                  }
                }
                """);
        String vpJwt = unsignedJwt("""
                {
                  "type": ["VerifiablePresentation"],
                  "verifiableCredential": ["%s"]
                }
                """.formatted(vcJwt));

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("VerifiableCredential", "IDCredential")),
                List.of(List.of("credentialSubject", "given_name")),
                null));

        assertDoesNotThrow(() -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
        assertDoesNotThrow(() -> DcqlPresentationValidator.validatePresentation(query, vpJwt));
    }

    @Test
    void rejectsJwtVcJsonPresentationWithMismatchedTypeValues() {
        String vcJwt = unsignedJwt("""
                {
                  "type": ["VerifiableCredential", "OtherCredential"],
                  "credentialSubject": {"given_name": "Max"}
                }
                """);
        String vpJwt = unsignedJwt("""
                {
                  "verifiableCredential": ["%s"]
                }
                """.formatted(vcJwt));

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("VerifiableCredential", "IDCredential")),
                List.of(List.of("credentialSubject", "given_name")),
                null));

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
    }

    @Test
    void rejectsJwtVcJsonPresentationMissingRequestedClaim() {
        String vcJwt = unsignedJwt("""
                {
                  "type": ["VerifiableCredential", "IDCredential"],
                  "credentialSubject": {"given_name": "Max"}
                }
                """);
        String vpJwt = unsignedJwt("""
                {
                  "verifiableCredential": ["%s"]
                }
                """.formatted(vcJwt));

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("VerifiableCredential", "IDCredential")),
                List.of(List.of("credentialSubject", "family_name")),
                null));

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
    }

    private static String unsignedJwt(String jsonPayload) {
        String header = base64Url("{\"alg\":\"none\"}");
        String payload = base64Url(jsonPayload.strip());
        return header + "." + payload + ".";
    }

    private static String base64Url(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
