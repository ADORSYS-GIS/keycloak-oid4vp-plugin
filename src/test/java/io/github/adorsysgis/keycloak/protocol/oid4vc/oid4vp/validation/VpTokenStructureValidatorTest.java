package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class VpTokenStructureValidatorTest {

    private final VpTokenStructureValidator validator = new VpTokenStructureValidator();

    @Test
    void acceptsMatchingVpToken() throws Exception {
        DcqlQuery query = singleCredentialQuery("cred-1", false);
        Map<String, List<String>> vpToken = Map.of("cred-1", List.of("eyJhbGciOiJIUzI1NiJ9.abc.def"));

        Map<String, List<String>> validated = validator.validate(vpToken, query);
        assertEquals(vpToken, validated);
    }

    @Test
    void acceptsAlternativeCredentialSetOption() throws Exception {
        Credential credA = credential("cred-a", false);
        Credential credB = credential("cred-b", false);

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of("cred-a"), List.of("cred-b")));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credA, credB));
        query.setCredentialSets(List.of(credentialSet));

        Map<String, List<String>> vpToken = Map.of("cred-b", List.of("vp"));

        Map<String, List<String>> validated = validator.validate(vpToken, query);
        assertEquals(vpToken, validated);
    }

    @Test
    void rejectsUnexpectedCredentialId() {
        DcqlQuery query = singleCredentialQuery("cred-1", false);
        Map<String, List<String>> vpToken = Map.of("cred-1", List.of("vp"), "extra-id", List.of("vp2"));

        VpTokenValidationException error =
                assertThrows(VpTokenValidationException.class, () -> validator.validate(vpToken, query));

        assertEquals(VpTokenValidationException.Phase.STRUCTURE, error.getPhase());
    }

    @Test
    void rejectsMissingCredentialIdWhenNoCredentialSets() {
        DcqlQuery query = singleCredentialQuery("cred-1", false);
        Map<String, List<String>> vpToken = Map.of("other-id", List.of("vp"));

        assertThrows(VpTokenValidationException.class, () -> validator.validate(vpToken, query));
    }

    @Test
    void rejectsMissingRequiredCredentialSetOption() {
        Credential credA = credential("cred-a", false);
        Credential credB = credential("cred-b", false);

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of("cred-a", "cred-b")));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credA, credB));
        query.setCredentialSets(List.of(credentialSet));

        Map<String, List<String>> vpToken = Map.of("cred-a", List.of("vp"));

        assertThrows(VpTokenValidationException.class, () -> validator.validate(vpToken, query));
    }

    @Test
    void rejectsCredentialOutsideSatisfiedCredentialSets() {
        Credential credA = credential("cred-a", false);
        Credential credB = credential("cred-b", false);
        Credential credC = credential("cred-c", false);

        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of("cred-a"), List.of("cred-b")));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credA, credB, credC));
        query.setCredentialSets(List.of(credentialSet));

        Map<String, List<String>> vpToken = Map.of(
                "cred-a", List.of("vp"),
                "cred-c", List.of("vp2"));

        VpTokenValidationException error =
                assertThrows(VpTokenValidationException.class, () -> validator.validate(vpToken, query));

        assertEquals(VpTokenValidationException.Phase.STRUCTURE, error.getPhase());
        assertTrue(error.getMessage().contains("outside satisfied DCQL credential_sets"));
    }

    @Test
    void rejectsMultiplePresentationsWhenNotAllowed() {
        Credential credential = credential("cred-1", false);

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));

        Map<String, List<String>> vpToken = Map.of("cred-1", List.of("vp1", "vp2"));

        assertThrows(VpTokenValidationException.class, () -> validator.validate(vpToken, query));
    }

    private static DcqlQuery singleCredentialQuery(String id, boolean multiple) {
        Credential credential = credential(id, multiple);

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        return query;
    }

    private static Credential credential(String id, boolean multiple) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMultiple(multiple);
        return credential;
    }
}
