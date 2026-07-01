package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;

class DcqlQueryValidatorTest {

    @Test
    void rejectsEmptyVctValuesForSdJwt() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of());
        credential.setMeta(meta);

        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("meta.vct_values must be non-empty for dc+sd-jwt credential queries", error.getMessage());
    }

    @Test
    void rejectsVpWrapperPathsForSdJwt() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("vp", "sub"));
        credential.setClaims(List.of(claim));

        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dc+sd-jwt claim paths must be relative to the VC root, not the VP wrapper: [vp, sub]",
                error.getMessage());
    }

    @Test
    void rejectsArrayIndexPathSegments() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("addresses", "0", "street"));
        credential.setClaims(List.of(claim));

        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query claim path supports object property names only; array indexes and null wildcards are not supported",
                error.getMessage());
    }

    @Test
    void acceptsNestedObjectKeyPathSegments() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("address", "street_address"));
        credential.setClaims(List.of(claim));

        assertDoesNotThrow(
                () -> DcqlQueryValidator.validateCredential(credential), "Should accept nested object-key claim paths");
    }

    @Test
    void rejectsInvalidCredentialIdSyntax() {
        Credential credential = sdJwtCredential("cred.1", List.of());
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query credential id must consist of alphanumeric, underscore, or hyphen characters: cred.1",
                error.getMessage());
    }

    @Test
    void rejectsDuplicateCredentialIds() {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(sdJwtCredential("cred-1", List.of()), sdJwtCredential("cred-1", List.of())));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateQuery(query));
        assertEquals("dcql_query credential id must be unique: cred-1", error.getMessage());
    }

    @Test
    void rejectsClaimSetsWithoutClaims() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        credential.setClaimSets(List.of(List.of("claim-1")));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim_sets must not be present when claims is absent", error.getMessage());
    }

    @Test
    void rejectsUnknownClaimIdInClaimSets() {
        Claim claim = new Claim();
        claim.setId("given_name");
        claim.setPath(List.of("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        credential.setClaimSets(List.of(List.of("family_name")));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query claim_sets references unknown claim id: family_name in credential cred-1",
                error.getMessage());
    }

    @Test
    void rejectsDuplicateClaimIds() {
        Claim first = new Claim();
        first.setId("claim-1");
        first.setPath(List.of("given_name"));
        Claim second = new Claim();
        second.setId("claim-1");
        second.setPath(List.of("family_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(first, second));
        credential.setClaimSets(List.of(List.of("claim-1")));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim id must be unique within credential cred-1: claim-1", error.getMessage());
    }

    @Test
    void rejectsDuplicateClaimPaths() {
        Claim first = new Claim();
        first.setId("claim-1");
        first.setPath(List.of("given_name"));
        Claim second = new Claim();
        second.setId("claim-2");
        second.setPath(List.of("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(first, second));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query must not reference the same claim more than once in credential cred-1: [given_name]",
                error.getMessage());
    }

    @Test
    void acceptsValidClaimSets() {
        Claim givenName = new Claim();
        givenName.setId("given_name");
        givenName.setPath(List.of("given_name"));
        Claim familyName = new Claim();
        familyName.setId("family_name");
        familyName.setPath(List.of("family_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(givenName, familyName));
        credential.setClaimSets(List.of(List.of("given_name", "family_name"), List.of("given_name")));
        assertDoesNotThrow(
                () -> DcqlQueryValidator.validateCredential(credential), "Should accept valid claim_sets options");
    }

    @Test
    void acceptsStringClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("age"));
        claim.setValues(List.of("adult", "verified"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertDoesNotThrow(
                () -> DcqlQueryValidator.validateCredential(credential), "Should accept string claim values");
    }

    @Test
    void rejectsEmptyClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("age"));
        claim.setValues(List.of());
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim values must be non-empty when present", error.getMessage());
    }

    @Test
    void rejectsBlankStringClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("age"));
        claim.setValues(List.of(""));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim values must not contain blank entries", error.getMessage());
    }

    @Test
    void rejectsNullQuery() {
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateQuery(null));
        assertEquals("dcql_query.credentials must be non-empty", error.getMessage());
    }

    @Test
    void rejectsNullCredential() {
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(null));
        assertEquals("dcql_query credential must not be null", error.getMessage());
    }

    @Test
    void rejectsBlankCredentialFormat() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        credential.setFormat("  ");
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query credential format must be non-empty", error.getMessage());
    }

    @Test
    void rejectsNullCredentialMeta() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(null);
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query credential meta must be present for format " + VCFormat.SD_JWT_VC, error.getMessage());
    }

    @Test
    void rejectsUnsupportedCredentialFormat() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat("jwt_vc_json");
        credential.setMeta(new Meta());
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("Unsupported dcql_query credential format: jwt_vc_json", error.getMessage());
    }

    @Test
    void rejectsBlankVctValueInMeta() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        credential.getMeta().setVctValues(List.of("https://example.com/vct", "  "));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("meta.vct_values must not contain blank entries", error.getMessage());
    }

    @Test
    void rejectsEmptyClaimPath() {
        Claim claim = new Claim();
        claim.setPath(List.of());
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim path must be non-empty", error.getMessage());
    }

    @Test
    void rejectsBlankClaimPathSegment() {
        Claim claim = new Claim();
        claim.setPath(List.of("given_name", "  "));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim path segments must be non-empty", error.getMessage());
    }

    @Test
    void rejectsNullWildcardPathSegment() {
        Claim claim = new Claim();
        claim.setPath(List.of("addresses", "null", "street"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query claim path supports object property names only; array indexes and null wildcards are not supported",
                error.getMessage());
    }

    @Test
    void rejectsVerifiableCredentialWrapperPath() {
        Claim claim = new Claim();
        claim.setPath(List.of("verifiableCredential", "sub"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dc+sd-jwt claim paths must be relative to the VC root, not the VP wrapper: [verifiableCredential, sub]",
                error.getMessage());
    }

    @Test
    void rejectsDuplicateClaimIdsWithoutClaimSets() {
        Claim first = new Claim();
        first.setId("claim-1");
        first.setPath(List.of("given_name"));
        Claim second = new Claim();
        second.setId("claim-1");
        second.setPath(List.of("family_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(first, second));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals("dcql_query claim id must be unique within credential cred-1: claim-1", error.getMessage());
    }

    @Test
    void rejectsEmptyClaimSetsOption() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        credential.setClaimSets(List.of(List.of()));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query claim_sets option must be a non-empty array for credential cred-1", error.getMessage());
    }

    @Test
    void rejectsBlankClaimIdInClaimSets() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        credential.setClaimSets(List.of(List.of("  ")));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
        assertEquals(
                "dcql_query claim_sets must reference non-empty claim ids for credential cred-1", error.getMessage());
    }

    @Test
    void rejectsUnknownCredentialIdInCredentialSets() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of(List.of("missing-cred")));
        query.setCredentialSets(List.of(credentialSet));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateQuery(query));
        assertEquals("dcql_query credential_sets references unknown credential id: missing-cred", error.getMessage());
    }

    @Test
    void rejectsEmptyCredentialSetOptions() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(List.of());
        query.setCredentialSets(List.of(credentialSet));
        IllegalArgumentException error =
                assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateQuery(query));
        assertEquals("dcql_query credential_sets.options must be non-empty when present", error.getMessage());
    }

    @Test
    void acceptsValidSdJwtCredentialQuery() {
        var query = new SdJwtCredentialConstrainer()
                .buildQuery(
                        SdJwtCredentialConstrainer.QuerySpec.of(List.of("https://example.com/vct"), List.of("sub")));
        assertDoesNotThrow(
                () -> DcqlQueryValidator.validateQuery(query), "Should accept a valid SD-JWT credential query");
    }

    private static Credential sdJwtCredential(String id, List<Claim> claims) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);
        credential.setClaims(claims);
        return credential;
    }
}
