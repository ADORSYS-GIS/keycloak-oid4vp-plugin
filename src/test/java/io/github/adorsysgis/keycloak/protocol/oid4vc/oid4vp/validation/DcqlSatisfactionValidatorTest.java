package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Meta;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.keycloak.sdjwt.IssuerSignedJWT;
import org.keycloak.sdjwt.vp.SdJwtVP;

class DcqlSatisfactionValidatorTest {

    private final DcqlSatisfactionValidator validator = new DcqlSatisfactionValidator();

    @Test
    void rejectsClaimWhenValuesDoNotMatch() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "bob");
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void rejectsSdJwtCredentialQueryWithoutVctValues() {
        Credential credentialQuery = credentialWithId("cred-1");
        credentialQuery.setMeta(new Meta());
        SdJwtVP presentation = mockPresentationWithVctOnly();
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void rejectsSdJwtCredentialQueryWithNullMeta() {
        Credential credentialQuery = credentialWithId("cred-1");
        credentialQuery.setMeta(null);
        SdJwtVP presentation = mockPresentationWithVctOnly();
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void rejectsClaimSetsWhenClaimsAbsent() {
        Credential credentialQuery = credentialWithId("cred-1");
        credentialQuery.setClaimSets(List.of(List.of("claim-1")));
        SdJwtVP presentation = mockPresentationWithVctOnly();
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void acceptsClaimWhenValuesMatch() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationPasses(List.of(presented), query);
    }

    @Test
    void acceptsClaimWhenBooleanValuesMatch() {
        Credential credentialQuery = credentialWithClaim("adult", List.of(true));
        SdJwtVP presentation = mockPresentationWithClaim("adult", true);
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationPasses(List.of(presented), query);
    }

    @Test
    void rejectsDuplicatePresentationWhenMultipleIsFalse() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential first = new PresentedCredential("cred-1", credentialQuery, "vp-1", presentation);
        PresentedCredential second = new PresentedCredential("cred-1", credentialQuery, "vp-2", presentation);

        assertValidationThrows(List.of(first, second), query);
    }

    @Test
    void rejectsUnknownCredentialQueryIdWhenCredentialSetsAbsent() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential presented = new PresentedCredential("unknown-id", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void rejectsMissingCredentialQueryIdWhenCredentialSetsAbsent() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");

        Credential secondQuery = credentialWithClaim("email", List.of("alice@example.com"));
        secondQuery.setId("cred-2");
        DcqlQuery query = queryWithCredentials(credentialQuery, secondQuery);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertValidationThrows(List.of(presented), query);
    }

    @Test
    void acceptsSingleCredentialSetOption() {
        Credential pid = credentialWithId("pid");
        Credential reducedPid = credentialWithId("reduced_pid");
        DcqlQuery query =
                queryWithCredentialSet(List.of(pid, reducedPid), List.of(List.of("pid"), List.of("reduced_pid")));

        SdJwtVP presentation = mockPresentationWithVctOnly();
        PresentedCredential presented = new PresentedCredential("pid", pid, "vp", presentation);

        assertValidationPasses(List.of(presented), query);
    }

    @Test
    void rejectsCredentialsFromMultipleOptionsInSameCredentialSet() {
        Credential pid = credentialWithId("pid");
        Credential reducedPid = credentialWithId("reduced_pid");
        DcqlQuery query =
                queryWithCredentialSet(List.of(pid, reducedPid), List.of(List.of("pid"), List.of("reduced_pid")));

        SdJwtVP presentation = mockPresentationWithVctOnly();
        PresentedCredential first = new PresentedCredential("pid", pid, "vp-1", presentation);
        PresentedCredential second = new PresentedCredential("reduced_pid", reducedPid, "vp-2", presentation);

        assertValidationThrows(List.of(first, second), query);
    }

    @Test
    void acceptsCredentialsFromMultipleRequiredCredentialSets() {
        Credential pid = credentialWithId("pid");
        Credential reducedPid = credentialWithId("reduced_pid");
        Credential address = credentialWithId("address");

        CredentialSet identitySet = new CredentialSet();
        identitySet.setOptions(List.of(List.of("pid"), List.of("reduced_pid")));

        CredentialSet addressSet = new CredentialSet();
        addressSet.setOptions(List.of(List.of("address")));

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(pid, reducedPid, address));
        query.setCredentialSets(List.of(identitySet, addressSet));

        SdJwtVP presentation = mockPresentationWithVctOnly();
        PresentedCredential pidPresentation = new PresentedCredential("pid", pid, "vp-1", presentation);
        PresentedCredential addressPresentation = new PresentedCredential("address", address, "vp-2", presentation);

        assertValidationPasses(List.of(pidPresentation, addressPresentation), query);
    }

    @Test
    void acceptsMultiplePresentationsWhenMultipleIsTrue() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        credentialQuery.setMultiple(true);
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");
        DcqlQuery query = queryWithCredentials(credentialQuery);

        PresentedCredential first = new PresentedCredential("cred-1", credentialQuery, "vp-1", presentation);
        PresentedCredential second = new PresentedCredential("cred-1", credentialQuery, "vp-2", presentation);

        assertValidationPasses(List.of(first, second), query);
    }

    private void assertValidationPasses(List<PresentedCredential> presentations, DcqlQuery query) {
        try {
            validator.validate(presentations, query);
        } catch (VpTokenValidationException e) {
            throw new AssertionError("Expected validation to pass", e);
        }
    }

    private void assertValidationThrows(List<PresentedCredential> presentations, DcqlQuery query) {
        assertThrows(VpTokenValidationException.class, () -> validator.validate(presentations, query));
    }

    private static DcqlQuery queryWithCredentials(Credential... credentials) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credentials));
        return query;
    }

    private static DcqlQuery queryWithCredentialSet(List<Credential> credentials, List<List<String>> options) {
        CredentialSet credentialSet = new CredentialSet();
        credentialSet.setOptions(options);

        DcqlQuery query = new DcqlQuery();
        query.setCredentials(credentials);
        query.setCredentialSets(List.of(credentialSet));
        return query;
    }

    private static Credential credentialWithId(String id) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(new Meta());
        credential.getMeta().setVctValues(List.of("https://example.com/vct"));
        return credential;
    }

    private static Credential credentialWithClaim(String claimName, List<Object> values) {
        Claim claim = new Claim();
        claim.setPath(List.<Object>of(claimName));
        claim.setValues(values);

        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(new Meta());
        credential.getMeta().setVctValues(List.of("https://example.com/vct"));
        credential.setClaims(List.of(claim));
        return credential;
    }

    private static SdJwtVP mockPresentationWithVctOnly() {
        SdJwtVP presentation = mock(SdJwtVP.class);
        IssuerSignedJWT issuerSignedJwt = mock(IssuerSignedJWT.class);
        var payload = JsonNodeFactory.instance.objectNode();
        payload.put("vct", "https://example.com/vct");
        when(presentation.getIssuerSignedJWT()).thenReturn(issuerSignedJwt);
        when(issuerSignedJwt.getPayload()).thenReturn(payload);
        when(presentation.getDisclosuresString()).thenReturn(List.of());
        return presentation;
    }

    private static SdJwtVP mockPresentationWithClaim(String claimName, Object claimValue) {
        SdJwtVP presentation = mock(SdJwtVP.class);
        IssuerSignedJWT issuerSignedJwt = mock(IssuerSignedJWT.class);
        var payload = JsonNodeFactory.instance.objectNode();
        payload.put("vct", "https://example.com/vct");
        if (claimValue instanceof Boolean booleanValue) {
            payload.put(claimName, booleanValue);
        } else {
            payload.put(claimName, String.valueOf(claimValue));
        }
        when(presentation.getIssuerSignedJWT()).thenReturn(issuerSignedJwt);
        when(issuerSignedJwt.getPayload()).thenReturn(payload);
        when(presentation.getDisclosuresString()).thenReturn(List.of());
        return presentation;
    }
}
