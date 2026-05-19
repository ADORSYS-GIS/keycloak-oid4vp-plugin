package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
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

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertThrows(
                VpTokenValidationException.class,
                () -> validator.validate(List.of(presented), queryWithCredentials(credentialQuery)));
    }

    @Test
    void acceptsClaimWhenValuesMatch() {
        Credential credentialQuery = credentialWithClaim("username", List.of("alice"));
        SdJwtVP presentation = mockPresentationWithClaim("username", "alice");

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertDoesNotThrow(() -> validator.validate(List.of(presented), queryWithCredentials(credentialQuery)));
    }

    @Test
    void acceptsClaimWhenBooleanValuesMatch() {
        Credential credentialQuery = credentialWithClaim("adult", List.of(true));
        SdJwtVP presentation = mockPresentationWithClaim("adult", true);

        PresentedCredential presented = new PresentedCredential("cred-1", credentialQuery, "vp", presentation);

        assertDoesNotThrow(() -> validator.validate(List.of(presented), queryWithCredentials(credentialQuery)));
    }

    private static DcqlQuery queryWithCredentials(Credential credential) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credential));
        return query;
    }

    private static Credential credentialWithClaim(String claimName, List<Object> values) {
        Claim claim = new Claim();
        claim.setPath(List.of(claimName));
        claim.setValues(values);

        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat(VCFormat.SD_JWT_VC);
        credential.setMeta(new Meta());
        credential.getMeta().setVctValues(List.of("https://example.com/vct"));
        credential.setClaims(List.of(claim));
        return credential;
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
