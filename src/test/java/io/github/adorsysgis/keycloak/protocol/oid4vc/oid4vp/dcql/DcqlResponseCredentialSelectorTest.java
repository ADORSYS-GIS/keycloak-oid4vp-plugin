package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DcqlResponseCredentialSelectorTest {

    @Test
    void acceptsCompleteRequiredCombination() {
        DcqlQuery query = query(List.of("pid", "residence"), List.of(required(List.of(List.of("pid", "residence")))));

        assertEquals(
                Set.of("pid", "residence"),
                DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid", "residence")));
    }

    @Test
    void acceptsSubsetOptionWhenCompleteResponseMatchesLargerOption() {
        DcqlQuery query = query(
                List.of("pid", "residence"), List.of(required(List.of(List.of("pid"), List.of("pid", "residence")))));

        assertEquals(
                Set.of("pid", "residence"),
                DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid", "residence")));
    }

    @Test
    void acceptsOptionalCredentialSetWhenItAccountsForPresentedCredential() {
        DcqlQuery query = query(
                List.of("pid", "residence"),
                List.of(required(List.of(List.of("pid"))), optional(List.of(List.of("residence")))));

        assertEquals(
                Set.of("pid", "residence"),
                DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid", "residence")));
    }

    @Test
    void acceptsCredentialSharedByMultipleSets() {
        DcqlQuery query =
                query(List.of("pid"), List.of(required(List.of(List.of("pid"))), required(List.of(List.of("pid")))));

        assertEquals(Set.of("pid"), DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid")));
    }

    @Test
    void rejectsPresentedCredentialNotCoveredBySelectedOptions() {
        DcqlQuery query = query(List.of("pid", "residence"), List.of(required(List.of(List.of("pid")))));

        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid", "residence")));
    }

    @Test
    void rejectsCredentialSetWithoutOptions() {
        DcqlQuery query = query(List.of("pid"), List.of(required(null)));

        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid")));
    }

    @Test
    void fallsBackToAllCredentialsRequiredWhenCredentialSetsAreMissing() {
        DcqlQuery query = query(List.of("pid", "residence"), null);

        assertDoesNotThrow(
                () -> DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid", "residence")));
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlResponseCredentialSelector.selectPresentedCredentialIds(query, Set.of("pid")));
    }

    private static DcqlQuery query(List<String> credentialIds, List<CredentialSet> credentialSets) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentialIds.stream()
                .map(DcqlResponseCredentialSelectorTest::credential)
                .toList());
        query.setCredentialSets(credentialSets);
        return query;
    }

    private static Credential credential(String id) {
        Credential credential = new Credential();
        credential.setId(id);
        return credential;
    }

    private static CredentialSet required(List<List<String>> options) {
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setRequired(Boolean.TRUE);
        credentialSet.setOptions(options);
        return credentialSet;
    }

    private static CredentialSet optional(List<List<String>> options) {
        CredentialSet credentialSet = required(options);
        credentialSet.setRequired(Boolean.FALSE);
        return credentialSet;
    }
}
