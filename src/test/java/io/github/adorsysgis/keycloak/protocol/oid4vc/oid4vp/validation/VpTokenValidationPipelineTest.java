package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtAuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.VCFormat;
import org.keycloak.models.KeycloakSession;
import org.keycloak.util.JsonSerialization;

class VpTokenValidationPipelineTest {

    private final VpTokenValidationPipeline pipeline =
            new VpTokenValidationPipeline(new SdJwtPresentationValidator(mock(StatusListJwtFetcher.class)));

    @Test
    void rejectsUnsupportedCredentialFormat() throws Exception {
        Credential credential = new Credential();
        credential.setId("cred-1");
        credential.setFormat("jwt_vc_json");

        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credential));

        RequestObject requestObject =
                new RequestObject().setDcqlQuery(dcqlQuery).setNonce("nonce").setClientId("client");

        ResponseObject responseObject = responseWithVpToken(Map.of("cred-1", List.of("not-a-real-vp")));

        VpTokenValidationException error = assertThrows(
                VpTokenValidationException.class,
                () -> pipeline.validate(responseObject, validationContext(requestObject)));

        assertEquals(VpTokenValidationException.Phase.FORMAT, error.getPhase());
        assertEquals("Unsupported credential format: jwt_vc_json", error.getMessage());
    }

    @Test
    void requireSinglePresentationRejectsMultipleValidatedCredentials() throws Exception {
        PresentationFormatValidator acceptingValidator = new PresentationFormatValidator() {
            @Override
            public boolean supports(Credential credentialQuery) {
                return true;
            }

            @Override
            public ValidatedPresentation validate(
                    String encodedPresentation, Credential credentialQuery, VpTokenValidationContext context) {
                return new ValidatedPresentation(encodedPresentation, null);
            }
        };

        var pipeline = new VpTokenValidationPipeline(acceptingValidator);
        Credential credential = credential("cred-1");
        credential.setMultiple(true);

        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credential));

        RequestObject requestObject =
                new RequestObject().setDcqlQuery(dcqlQuery).setNonce("nonce").setClientId("client");

        ResponseObject responseObject = responseWithVpToken(Map.of("cred-1", List.of("vp-1", "vp-2")));
        VpTokenValidationResult result = pipeline.validate(responseObject, validationContext(requestObject));

        VpTokenValidationException error =
                assertThrows(VpTokenValidationException.class, result::requireSinglePresentation);

        assertEquals(VpTokenValidationException.Phase.STRUCTURE, error.getPhase());
        assertEquals("User authentication requires exactly one presented credential, found: 2", error.getMessage());
    }

    @Test
    void validatesOnlyPresentedCredentialsWhenCredentialSetsAllowAlternatives() throws Exception {
        Credential credA = credential("cred-a");
        Credential credB = credential("cred-b");

        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credA, credB));
        dcqlQuery.setCredentialSets(List.of(credentialSet(List.of(List.of("cred-a"), List.of("cred-b")))));

        RequestObject requestObject =
                new RequestObject().setDcqlQuery(dcqlQuery).setNonce("nonce").setClientId("client");

        ResponseObject responseObject = responseWithVpToken(Map.of("cred-b", List.of("not-a-real-vp")));

        // Structure passes; format validation fails on unparseable VP — proves no NPE on missing cred-a.
        VpTokenValidationException error = assertThrows(
                VpTokenValidationException.class,
                () -> pipeline.validate(responseObject, validationContext(requestObject)));

        assertEquals(VpTokenValidationException.Phase.STRUCTURE, error.getPhase());
    }

    private static ResponseObject responseWithVpToken(Map<String, List<String>> vpToken) throws Exception {
        return new ResponseObject(JsonSerialization.writeValueAsString(vpToken), "state");
    }

    private static VpTokenValidationContext validationContext(RequestObject requestObject) {
        KeycloakSession session = mock(KeycloakSession.class);
        SdJwtAuthRequirements authRequirements = mock(SdJwtAuthRequirements.class);
        return new VpTokenValidationContext(session, requestObject, authRequirements, "nonce", "client");
    }

    private static io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet credentialSet(
            List<List<String>> options) {
        var credentialSet = new io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.CredentialSet();
        credentialSet.setOptions(options);
        return credentialSet;
    }

    private static Credential credential(String id) {
        Credential credential = new Credential();
        credential.setId(id);
        credential.setFormat(VCFormat.SD_JWT_VC);
        return credential;
    }
}
