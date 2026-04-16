package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.ECTestUtils;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.keycloak.common.crypto.CryptoIntegration;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwk.JWKParser;

class EphemeralKeyUtilsTest {

    public final String MESSAGE = """
        Morning spills gold across quiet streets,
        A stray breeze hums through half-open doors.
        Footsteps echo stories never finished,
        While shadows stretch, reluctant to fade.
        """;

    @BeforeAll
    static void setup() {
        CryptoIntegration.init(ExtendedCertificateUtilsTest.class.getClassLoader());
    }

    static Stream<Arguments> jweEncryptionAlgorithms() {
        return Stream.of(
                Arguments.of(JWEConstants.ECDH_ES, JWEConstants.A128GCM),
                Arguments.of(JWEConstants.ECDH_ES, JWEConstants.A192GCM),
                Arguments.of(JWEConstants.ECDH_ES, JWEConstants.A256GCM),
                Arguments.of(JWEConstants.ECDH_ES_A128KW, JWEConstants.A128GCM),
                Arguments.of(JWEConstants.ECDH_ES_A192KW, JWEConstants.A256GCM));
    }

    @ParameterizedTest
    @MethodSource("jweEncryptionAlgorithms")
    public void testEncryptDecryptMessage(String jweAlg, String jweEncAlg) throws Exception {
        // Generate key
        EphemeralKeyUtils.EphemeralKey key = EphemeralKeyUtils.generateEphemeralECDHKey();
        ECPublicKey publicKey = (ECPublicKey) JWKParser.create(key.publicKey()).toPublicKey();
        ECPrivateKey privateKey = key.privateKey();

        // Encrypt message
        String encMsg = ECTestUtils.encryptMessage(MESSAGE, publicKey, jweAlg, jweEncAlg);

        // Decrypt message
        String decMsg = EphemeralKeyUtils.decrypt(encMsg, privateKey);
        assertEquals(MESSAGE, decMsg);
    }

    @Test
    public void testEncryptDecryptMessage_WithBase64RoundTrip() throws Exception {
        // Generate key
        EphemeralKeyUtils.EphemeralKey key = EphemeralKeyUtils.generateEphemeralECDHKey();
        ECPublicKey publicKey = (ECPublicKey) JWKParser.create(key.publicKey()).toPublicKey();
        ECPrivateKey privateKey = key.privateKey();

        // Round-trip conversion of private key
        String base64 = EphemeralKeyUtils.toBase64String(privateKey);
        ECPrivateKey roundTrippedPrivateKey = EphemeralKeyUtils.privateKeyFromBase64(base64);

        // Encrypt message
        String encMsg = ECTestUtils.encryptMessage(MESSAGE, publicKey);

        // Decrypt message
        assertEquals(MESSAGE, EphemeralKeyUtils.decrypt(encMsg, privateKey));
        assertEquals(MESSAGE, EphemeralKeyUtils.decrypt(encMsg, roundTrippedPrivateKey));
    }
}
