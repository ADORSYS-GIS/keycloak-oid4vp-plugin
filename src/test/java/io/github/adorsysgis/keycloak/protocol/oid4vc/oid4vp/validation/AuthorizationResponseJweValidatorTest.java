package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.EphemeralKeyUtils.EphemeralKey;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import java.security.interfaces.ECPublicKey;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.util.JsonSerialization;

class AuthorizationResponseJweValidatorTest {

    @BeforeAll
    static void initCrypto() {
        CryptoIntegration.init(AuthorizationResponseJweValidatorTest.class.getClassLoader());
    }

    @Test
    void validate_acceptsWellFormedJweMatchingAdvertisedJwks() throws Exception {
        EphemeralKey ephemeralKey = EphemeralKeyUtils.generateEphemeralECDHKey();
        var pubJwk = ephemeralKey.publicKey();
        String kid = pubJwk.getKeyId();
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[] {pubJwk});

        AuthorizationContext ctx = contextWithJwks(jwks, kid);

        String payload = JsonSerialization.writeValueAsString(Map.of("vp_token", Map.of()));
        ECPublicKey pub = (ECPublicKey) JWKParser.create(pubJwk).toPublicKey();
        String jwe = ECTestUtils.encryptMessage(payload, pub, JWEConstants.ECDH_ES, JWEConstants.A128GCM, kid);

        assertDoesNotThrow(() -> AuthorizationResponseJweValidator.validate(jwe, ctx));
    }

    @Test
    void validate_rejectsMalformedCompactJwe() {
        AuthorizationContext ctx = contextWithJwks(emptyJwksFromEphemeral(), "any");
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class, () -> AuthorizationResponseJweValidator.validate("not-a-jwe", ctx));
        assertTrue(ex.getMessage().contains("not a compact JWE"));
    }

    @Test
    void validate_rejectsUnsupportedKeyManagementAlgorithm() throws Exception {
        EphemeralKey ephemeralKey = EphemeralKeyUtils.generateEphemeralECDHKey();
        var pubJwk = ephemeralKey.publicKey();
        String kid = pubJwk.getKeyId();
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[] {pubJwk});

        AuthorizationContext ctx = contextWithJwks(jwks, kid);

        String payload = JsonSerialization.writeValueAsString(Map.of("vp_token", Map.of()));
        ECPublicKey pub = (ECPublicKey) JWKParser.create(pubJwk).toPublicKey();
        String jwe = ECTestUtils.encryptMessage(payload, pub, JWEConstants.ECDH_ES_A128KW, JWEConstants.A128GCM, kid);

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class, () -> AuthorizationResponseJweValidator.validate(jwe, ctx));
        assertTrue(ex.getMessage().contains("ECDH-ES"));
    }

    private static JSONWebKeySet emptyJwksFromEphemeral() {
        EphemeralKey ephemeralKey = EphemeralKeyUtils.generateEphemeralECDHKey();
        JSONWebKeySet jwks = new JSONWebKeySet();
        jwks.setKeys(new JWK[] {ephemeralKey.publicKey()});
        return jwks;
    }

    private static AuthorizationContext contextWithJwks(JSONWebKeySet jwks, String expectedKid) {
        ClientMetadata metadata = new ClientMetadata().setJwks(jwks);
        RequestObject ro = new RequestObject().setClientMetadata(metadata);
        return new AuthorizationContext().setRequestObject(ro).setExpectedEncryptionKid(expectedKid);
    }
}
