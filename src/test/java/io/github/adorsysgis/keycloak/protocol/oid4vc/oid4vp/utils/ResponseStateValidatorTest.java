package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ResponseObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.JsonWebToken;

class ResponseStateValidatorTest {

    private static final String REQUEST_ID = "session-marker.abc123";
    private static final String DUMMY_VP_TOKEN = "{}";

    @Test
    void requiresMatchingStateWhenAnyCredentialDisablesHolderBinding() throws Exception {
        DcqlQuery query = queryWithHolderBinding(false);
        ResponseObject response = new ResponseObject(DUMMY_VP_TOKEN, REQUEST_ID);

        assertDoesNotThrow(() -> ResponseStateValidator.validate(response, query, REQUEST_ID));
    }

    @Test
    void rejectsMissingStateWhenHolderBindingDisabled() throws Exception {
        DcqlQuery query = queryWithHolderBinding(false);
        ResponseObject response = new ResponseObject(DUMMY_VP_TOKEN, null);

        assertThrows(
                IllegalArgumentException.class, () -> ResponseStateValidator.validate(response, query, REQUEST_ID));
    }

    @Test
    void rejectsWrongStateWhenHolderBindingDisabled() throws Exception {
        DcqlQuery query = queryWithHolderBinding(false);
        ResponseObject response = new ResponseObject(DUMMY_VP_TOKEN, "wrong-state");

        assertThrows(
                IllegalArgumentException.class, () -> ResponseStateValidator.validate(response, query, REQUEST_ID));
    }

    @Test
    void rejectsMismatchedStateWhenHolderBindingRequired() throws Exception {
        DcqlQuery query = queryWithHolderBinding(true);
        ResponseObject response = new ResponseObject(DUMMY_VP_TOKEN, "wrong-state");

        assertThrows(
                IllegalArgumentException.class, () -> ResponseStateValidator.validate(response, query, REQUEST_ID));
    }

    @Test
    void allowsAbsentStateWhenHolderBindingRequired() throws Exception {
        DcqlQuery query = queryWithHolderBinding(true);
        ResponseObject response = new ResponseObject(DUMMY_VP_TOKEN, null);

        assertDoesNotThrow(() -> ResponseStateValidator.validate(response, query, REQUEST_ID));
    }

    @Test
    void requiresStateWhenAnyCredentialInQueryDisablesHolderBinding() throws Exception {
        Credential bound = credentialWithHolderBinding(true);
        Credential unbound = credentialWithHolderBinding(false);
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(bound, unbound));

        ResponseObject missingState = new ResponseObject(DUMMY_VP_TOKEN, null);
        assertThrows(
                IllegalArgumentException.class, () -> ResponseStateValidator.validate(missingState, query, REQUEST_ID));

        ResponseObject matchingState = new ResponseObject(DUMMY_VP_TOKEN, REQUEST_ID);
        assertDoesNotThrow(() -> ResponseStateValidator.validate(matchingState, query, REQUEST_ID));
    }

    private static DcqlQuery queryWithHolderBinding(boolean required) {
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(credentialWithHolderBinding(required)));
        return query;
    }

    private static Credential credentialWithHolderBinding(boolean required) {
        var queryMap = new SdJwtCredentialConstrainer.QueryMap(
                List.of("vct1"), List.of(JsonWebToken.SUBJECT, OAuth2Constants.USERNAME), required);
        return new SdJwtCredentialConstrainer()
                .generateDcqlQuery(queryMap)
                .getCredentials()
                .getFirst();
    }
}
