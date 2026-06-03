package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.RSATestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.SdJwtVPTestUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataSupport;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.crypto.AsymmetricSignatureSignerContext;
import org.keycloak.crypto.ECDSASignatureSignerContext;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.sdjwt.SdJwt;
import org.keycloak.sdjwt.vp.SdJwtVP;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

class SdJwtAuthenticatorTransactionDataTest {

    private static final String VCT = "https://credentials.example.com/identity_credential";
    private static final String NONCE = "nonce-value";
    private static final String AUD = "https://verifier.example";

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(SdJwtAuthenticatorTransactionDataTest.class.getClassLoader());
    }

    @Test
    void acceptsMatchingTransactionDataHashes() throws Exception {
        String wire = wireEntry("payment");
        String hash = hashForWire(wire);
        SdJwtVP sdJwt = presentationWithHashes(List.of(hash));

        AuthenticationSessionModel authSession = authSessionWithWire(List.of(wire));
        SdJwtAuthenticator authenticator = new SdJwtAuthenticator(mock(StatusListJwtFetcher.class));

        assertDoesNotThrow(() -> authenticator.validateTransactionData(authSession, sdJwt));
    }

    @Test
    void rejectsMismatchedTransactionDataHashes() throws Exception {
        String wire = wireEntry("payment");
        SdJwtVP sdJwt = presentationWithHashes(List.of("invalid-hash"));

        AuthenticationSessionModel authSession = authSessionWithWire(List.of(wire));
        SdJwtAuthenticator authenticator = new SdJwtAuthenticator(mock(StatusListJwtFetcher.class));

        assertThrows(IllegalArgumentException.class, () -> authenticator.validateTransactionData(authSession, sdJwt));
    }

    @Test
    void skipsValidationWhenNoTransactionDataOnSession() throws Exception {
        SdJwtVP sdJwt = presentationWithHashes(List.of("any"));
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getAuthNote(SdJwtAuthenticator.TRANSACTION_DATA_WIRE_KEY))
                .thenReturn(null);

        SdJwtAuthenticator authenticator = new SdJwtAuthenticator(mock(StatusListJwtFetcher.class));

        assertDoesNotThrow(() -> authenticator.validateTransactionData(authSession, sdJwt));
    }

    private static AuthenticationSessionModel authSessionWithWire(List<String> wireEntries) throws Exception {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);
        when(authSession.getAuthNote(SdJwtAuthenticator.TRANSACTION_DATA_WIRE_KEY))
                .thenReturn(JsonSerialization.writeValueAsString(wireEntries));
        return authSession;
    }

    private static SdJwtVP presentationWithHashes(List<String> hashes) throws Exception {
        JWK issuerJwk = SdJwtVPTestUtils.getKeycloakJwk();
        KeyWrapper issuerKey = RSATestUtils.getRsaKeyWrapper(issuerJwk);
        String sdJwt = SdJwt.builder()
                .withIssuerSignedJwt(SdJwtVPTestUtils.exampleIssuerSignedJwtForTest(
                        "https://example.com/realms/test", VCT, "user-id", "test-user"))
                .withIssuerSigningContext(new AsymmetricSignatureSignerContext(issuerKey))
                .build()
                .toSdJwtString();

        JWK holderKey = SdJwtVPTestUtils.getUserJwk();
        KeyWrapper holderKeyWrapper = ECTestUtils.getEcKeyWrapper(holderKey);
        String vp = SdJwtVP.of(sdJwt)
                .present(
                        null,
                        true,
                        JsonSerialization.mapper.valueToTree(buildKbJwtClaims(hashes)),
                        new ECDSASignatureSignerContext(holderKeyWrapper));
        return SdJwtVP.of(vp);
    }

    private static JsonWebToken buildKbJwtClaims(List<String> hashes) {
        JsonWebToken kbJwtClaims = new JsonWebToken();
        long currentTime = org.keycloak.common.util.Time.currentTime();
        kbJwtClaims.iat(currentTime);
        kbJwtClaims.exp(currentTime + SdJwtVPTestUtils.KB_JWT_LIFESPAN_SECS);
        kbJwtClaims.getOtherClaims().put(IDToken.NONCE, NONCE);
        kbJwtClaims.getOtherClaims().put(IDToken.AUD, AUD);
        if (hashes != null && !hashes.isEmpty()) {
            kbJwtClaims.getOtherClaims().put("transaction_data_hashes", hashes);
        }
        return kbJwtClaims;
    }

    private static String wireEntry(String type) {
        ObjectNode tx = JsonSerialization.mapper.createObjectNode();
        tx.put(TransactionDataSupport.TYPE_CLAIM, type);
        tx.putArray(TransactionDataSupport.CREDENTIAL_IDS_CLAIM).add("cred-1");
        return TransactionDataSupport.prepareWireEntry(TransactionDataSupport.encodeWireObject(tx), "cred-1");
    }

    private static String hashForWire(String wire) {
        return TransactionDataSupport.base64UrlEncodeHash(
                TransactionDataSupport.hashWireString(wire, TransactionDataSupport.DEFAULT_HASH_ALG));
    }
}
