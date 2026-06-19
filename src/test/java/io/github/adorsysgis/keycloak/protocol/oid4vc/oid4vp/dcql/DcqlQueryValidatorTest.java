package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.Arrays;
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

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
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
        claim.setPath(path("vp", "sub"));
        credential.setClaims(List.of(claim));

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void acceptsArrayIndexAndWildcardPathSegments() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("addresses", null, 0, "street"));
        credential.setClaims(List.of(claim));

        assertDoesNotThrow(() -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsNegativeArrayIndexPathSegments() {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        Meta meta = new Meta();
        meta.setVctValues(List.of("https://example.com/vct"));
        credential.setMeta(meta);

        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("addresses", -1));
        credential.setClaims(List.of(claim));

        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsInvalidCredentialIdSyntax() {
        Credential credential = sdJwtCredential("cred.1", List.of());
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsDuplicateCredentialIds() {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(sdJwtCredential("cred-1", List.of()), sdJwtCredential("cred-1", List.of())));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateQuery(query));
    }

    @Test
    void rejectsClaimSetsWithoutClaims() {
        Credential credential = sdJwtCredential("cred-1", List.of());
        credential.setClaimSets(List.of(List.of("claim-1")));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsUnknownClaimIdInClaimSets() {
        Claim claim = new Claim();
        claim.setId("given_name");
        claim.setPath(path("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        credential.setClaimSets(List.of(List.of("family_name")));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsDuplicateClaimIds() {
        Claim first = new Claim();
        first.setId("claim-1");
        first.setPath(path("given_name"));
        Claim second = new Claim();
        second.setId("claim-1");
        second.setPath(path("family_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(first, second));
        credential.setClaimSets(List.of(List.of("claim-1")));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsDuplicateClaimPaths() {
        Claim first = new Claim();
        first.setId("claim-1");
        first.setPath(path("given_name"));
        Claim second = new Claim();
        second.setId("claim-2");
        second.setPath(path("given_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(first, second));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void acceptsValidClaimSets() {
        Claim givenName = new Claim();
        givenName.setId("given_name");
        givenName.setPath(path("given_name"));
        Claim familyName = new Claim();
        familyName.setId("family_name");
        familyName.setPath(path("family_name"));
        Credential credential = sdJwtCredential("cred-1", List.of(givenName, familyName));
        credential.setClaimSets(List.of(List.of("given_name", "family_name"), List.of("given_name")));
        assertDoesNotThrow(() -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void acceptsStringIntegerAndBooleanClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("age"));
        claim.setValues(List.of("adult", 18, true));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertDoesNotThrow(() -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsEmptyClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("age"));
        claim.setValues(List.of());
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsUnsupportedClaimValueTypes() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("address"));
        claim.setValues(List.of(List.of("street")));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsNonIntegerNumberClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("score"));
        claim.setValues(List.of(1.5));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void rejectsNullClaimValues() {
        Claim claim = new Claim();
        claim.setId("claim-1");
        claim.setPath(path("age"));
        claim.setValues(Arrays.asList((Object) null));
        Credential credential = sdJwtCredential("cred-1", List.of(claim));
        assertThrows(IllegalArgumentException.class, () -> DcqlQueryValidator.validateCredential(credential));
    }

    @Test
    void acceptsValidSdJwtCredentialQuery() {
        var query = new SdJwtCredentialConstrainer()
                .buildQuery(
                        SdJwtCredentialConstrainer.QuerySpec.of(List.of("https://example.com/vct"), List.of("sub")));
        assertDoesNotThrow(() -> DcqlQueryValidator.validateQuery(query));
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

    private static List<Object> path(Object... segments) {
        return Arrays.asList(segments);
    }
}
