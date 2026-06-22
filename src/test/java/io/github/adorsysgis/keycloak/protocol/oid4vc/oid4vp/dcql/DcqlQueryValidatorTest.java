package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
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

        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject SD-JWT credential with empty vct_values");
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

        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject SD-JWT claim paths relative to the VP wrapper");
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

        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject array index path segments");
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
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject credential ids with invalid characters");
    }

    @Test
    void rejectsDuplicateCredentialIds() {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(sdJwtCredential("cred-1", List.of()), sdJwtCredential("cred-1", List.of())));
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateQuery(query),
                "Should reject duplicate credential ids in dcql_query");
    }

    @Test
    void rejectsClaimSetsWithoutClaims() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        credential.setClaimSets(List.of(List.of("claim-1")));
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject claim_sets when claims are absent");
    }

    @Test
    void rejectsUnknownClaimIdInClaimSets() {
        Claim claim = new Claim();
        claim.setId("given_name");
        claim.setPath(List.of("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        credential.setClaimSets(List.of(List.of("family_name")));
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject claim_sets that reference unknown claim ids");
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
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject duplicate claim ids within a credential");
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
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject duplicate claim paths within a credential");
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
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject empty claim values arrays");
    }

    @Test
    void rejectsBlankStringClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(List.of("age"));
        claim.setValues(List.of(""));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertThrows(
                IllegalArgumentException.class,
                () -> DcqlQueryValidator.validateCredential(credential),
                "Should reject blank claim values entries");
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
