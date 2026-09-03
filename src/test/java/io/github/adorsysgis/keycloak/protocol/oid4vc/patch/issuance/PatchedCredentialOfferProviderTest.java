package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.issuance;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.keycloak.protocol.oid4vc.model.AuthorizationCodeGrant.AUTH_CODE_GRANT_TYPE;
import static org.keycloak.protocol.oid4vc.model.PreAuthorizedCodeGrant.PRE_AUTH_GRANT_TYPE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferProvider;
import org.keycloak.protocol.oid4vc.issuance.credentialoffer.CredentialOfferState;

class PatchedCredentialOfferProviderTest {

    private static final List<String> CREDENTIAL_CONFIGURATION_IDS = List.of("credential-config");
    private static final String TARGET_CLIENT_ID = "offer-creating-client";
    private static final String TARGET_USER_ID = "target-user";
    private static final Integer EXPIRE_AT = 123456789;

    @Test
    void removesTargetClientForAuthorizationCodeGrant() {
        CredentialOfferProvider delegate = mock(CredentialOfferProvider.class);
        CredentialOfferState expected = mock(CredentialOfferState.class);
        UserModel user = mock(UserModel.class);
        when(delegate.createCredentialOffer(
                        user,
                        AUTH_CODE_GRANT_TYPE,
                        CREDENTIAL_CONFIGURATION_IDS,
                        null,
                        TARGET_USER_ID,
                        EXPIRE_AT))
                .thenReturn(expected);

        CredentialOfferState actual = new PatchedCredentialOfferProvider(delegate)
                .createCredentialOffer(
                        user,
                        AUTH_CODE_GRANT_TYPE,
                        CREDENTIAL_CONFIGURATION_IDS,
                        TARGET_CLIENT_ID,
                        TARGET_USER_ID,
                        EXPIRE_AT);

        assertSame(expected, actual);
        verify(delegate)
                .createCredentialOffer(
                        user,
                        AUTH_CODE_GRANT_TYPE,
                        CREDENTIAL_CONFIGURATION_IDS,
                        null,
                        TARGET_USER_ID,
                        EXPIRE_AT);
        verifyNoMoreInteractions(delegate);
    }

    static Stream<Arguments> grantsRetainingTargetClient() {
        return Stream.of(Arguments.of(PRE_AUTH_GRANT_TYPE), Arguments.of("custom-grant"), Arguments.of((String) null));
    }

    @ParameterizedTest
    @MethodSource("grantsRetainingTargetClient")
    void retainsTargetClientForAllOtherGrantTypes(String grantType) {
        CredentialOfferProvider delegate = mock(CredentialOfferProvider.class);
        CredentialOfferState expected = mock(CredentialOfferState.class);
        UserModel user = mock(UserModel.class);
        when(delegate.createCredentialOffer(
                        user,
                        grantType,
                        CREDENTIAL_CONFIGURATION_IDS,
                        TARGET_CLIENT_ID,
                        TARGET_USER_ID,
                        EXPIRE_AT))
                .thenReturn(expected);

        CredentialOfferState actual = new PatchedCredentialOfferProvider(delegate)
                .createCredentialOffer(
                        user,
                        grantType,
                        CREDENTIAL_CONFIGURATION_IDS,
                        TARGET_CLIENT_ID,
                        TARGET_USER_ID,
                        EXPIRE_AT);

        assertSame(expected, actual);
        verify(delegate)
                .createCredentialOffer(
                        user,
                        grantType,
                        CREDENTIAL_CONFIGURATION_IDS,
                        TARGET_CLIENT_ID,
                        TARGET_USER_ID,
                        EXPIRE_AT);
        verifyNoMoreInteractions(delegate);
    }

    @Test
    void closesDelegate() {
        CredentialOfferProvider delegate = mock(CredentialOfferProvider.class);

        new PatchedCredentialOfferProvider(delegate).close();

        verify(delegate).close();
        verifyNoMoreInteractions(delegate);
    }
}

