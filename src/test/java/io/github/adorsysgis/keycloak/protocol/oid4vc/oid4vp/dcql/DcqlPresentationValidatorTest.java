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
        String vcJwt = specVcJwt("""
                {
                  "type": ["VerifiableCredential", "IDCredential"],
                  "credentialSubject": {
                    "given_name": "Max",
                    "family_name": "Mustermann"
                  }
                }
                """);
        String vpJwt = specVpJwt(vcJwt);

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("IDCredential")), List.of(List.of("credentialSubject", "given_name")), null));

        assertDoesNotThrow(() -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
        assertDoesNotThrow(() -> DcqlPresentationValidator.validatePresentation(query, vpJwt));
    }

    @Test
    void rejectsJwtVcJsonPresentationWithMismatchedTypeValues() {
        String vcJwt = specVcJwt("""
                {
                  "type": ["VerifiableCredential", "OtherCredential"],
                  "credentialSubject": {"given_name": "Max"}
                }
                """);
        String vpJwt = specVpJwt(vcJwt);

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("IDCredential")), List.of(List.of("credentialSubject", "given_name")), null));

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
    }

    @Test
    void rejectsJwtVcJsonPresentationMissingRequestedClaim() {
        String vcJwt = specVcJwt("""
                {
                  "type": ["VerifiableCredential", "IDCredential"],
                  "credentialSubject": {"given_name": "Max"}
                }
                """);
        String vpJwt = specVpJwt(vcJwt);

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of("VerifiableCredential", "IDCredential")),
                List.of(List.of("credentialSubject", "family_name")),
                null));

        assertThrows(
                VerificationException.class,
                () -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
    }

    @Test
    void matchesTypeValuesAfterJsonLdContextExpansion() {
        String vcJwt = specVcJwt("""
                {
                  "@context": {
                    "@version": 1.1,
                    "VerifiableCredential": "https://www.w3.org/2018/credentials#VerifiableCredential",
                    "IDCredential": "https://example.org/credentials#IDCredential"
                  },
                  "type": ["VerifiableCredential", "IDCredential"],
                  "credentialSubject": {"given_name": "Max"}
                }
                """);
        String vpJwt = specVpJwt(vcJwt);

        DcqlQuery query = jwtVcConstrainer.buildQuery(new JwtVcJsonCredentialConstrainer.QuerySpec(
                List.of(List.of(
                        "https://www.w3.org/2018/credentials#VerifiableCredential",
                        "https://example.org/credentials#IDCredential")),
                List.of(List.of("credentialSubject", "given_name")),
                null));

        assertDoesNotThrow(() -> DcqlPresentationValidator.validateJwtVcJsonPresentation(query, vpJwt));
    }

    /** OpenID4VP 1.0 Appendix B.1.3.1.2: W3C VC content is nested under {@code vc} in the JWT payload. */
    private static String specVcJwt(String vcJson) {
        return unsignedJwt("""
                {
                  "iss": "https://example.gov/issuers/565049",
                  "vc": %s
                }
                """.formatted(vcJson.strip()));
    }

    /** OpenID4VP 1.0 Appendix B.1.3.1.5: VP content is nested under {@code vp} in the JWT payload. */
    private static String specVpJwt(String vcJwt) {
        return unsignedJwt("""
                {
                  "iss": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                  "nonce": "n-0S6_WzA2Mj",
                  "vp": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiablePresentation"],
                    "verifiableCredential": ["%s"]
                  }
                }
                """.formatted(vcJwt));
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
