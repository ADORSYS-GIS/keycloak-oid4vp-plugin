package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.SdJwtCredentialConstrainer;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.DcqlQuery;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.representations.JsonWebToken;

class ResponseStateValidatorTest {

    private static final String REQUEST_ID = "session-marker.abc123";

    @Test
    void requiresMatchingStateWhenAnyCredentialDisablesHolderBinding() {
        DcqlQuery query = queryWithHolderBinding(false);

        assertDoesNotThrow(() -> ResponseStateValidator.validate(REQUEST_ID, query, REQUEST_ID));
    }

    @Test
    void rejectsMissingStateWhenHolderBindingDisabled() {
        DcqlQuery query = queryWithHolderBinding(false);

        assertThrows(IllegalArgumentException.class, () -> ResponseStateValidator.validate(null, query, REQUEST_ID));
    }

    @Test
    void rejectsMissingStateOnWalletErrorPath() {
        DcqlQuery query = queryWithHolderBinding(false);

        assertThrows(IllegalArgumentException.class, () -> ResponseStateValidator.validate("", query, REQUEST_ID));
    }

    @Test
    void rejectsWrongStateWhenHolderBindingDisabled() {
        DcqlQuery query = queryWithHolderBinding(false);

        assertThrows(
                IllegalArgumentException.class,
                () -> ResponseStateValidator.validate("wrong-state", query, REQUEST_ID));
    }

    @Test
    void rejectsMismatchedStateWhenHolderBindingRequired() {
        DcqlQuery query = queryWithHolderBinding(true);

        assertThrows(
                IllegalArgumentException.class,
                () -> ResponseStateValidator.validate("wrong-state", query, REQUEST_ID));
    }

    @Test
    void allowsAbsentStateWhenHolderBindingRequired() {
        DcqlQuery query = queryWithHolderBinding(true);

        assertDoesNotThrow(() -> ResponseStateValidator.validate(null, query, REQUEST_ID));
    }

    @Test
    void requiresStateWhenAnyCredentialInQueryDisablesHolderBinding() {
        Credential bound = credentialWithHolderBinding(true);
        Credential unbound = credentialWithHolderBinding(false);
        DcqlQuery query = new DcqlQuery();
        query.setCredentials(List.of(bound, unbound));

        assertThrows(IllegalArgumentException.class, () -> ResponseStateValidator.validate(null, query, REQUEST_ID));

        assertDoesNotThrow(() -> ResponseStateValidator.validate(REQUEST_ID, query, REQUEST_ID));
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
