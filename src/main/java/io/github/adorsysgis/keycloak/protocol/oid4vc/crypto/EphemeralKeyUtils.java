package io.github.adorsysgis.keycloak.protocol.oid4vc.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import org.keycloak.common.crypto.CryptoConstants;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;

/**
 * Utility class for handling ephemeral ECDH keys and JWE decryption.
 */
public class EphemeralKeyUtils {

    private EphemeralKeyUtils() {
        // Private constructor to prevent instantiation
    }

    /**
     * Generates an ephemeral ECDH key pair on curve P-256.
     *
     * @return The generated JWK containing both public and private parts.
     */
    public static EphemeralKey generateEphemeralECDHKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.EC);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(CryptoConstants.EC_KEY_SECP256R1);
            kpg.initialize(ecSpec);

            KeyPair kp = kpg.generateKeyPair();
            JWK pubJwk = JWKBuilder.create().ec(kp.getPublic(), KeyUse.ENC);
            pubJwk.setAlgorithm(JWEConstants.ECDH_ES);

            return new EphemeralKey((ECPrivateKey) kp.getPrivate(), pubJwk);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Failed to generate ephemeral ECDH key", e);
        }
    }

    /**
     * Decrypts a JWE encrypted message using the provided EC private key.
     *
     * @param encryptedMessage The JWE string.
     * @param privateKey       The EC private key for decryption.
     * @return The decrypted message as a String.
     * @throws JWEException If decryption fails.
     */
    public static String decrypt(String encryptedMessage, ECPrivateKey privateKey) throws JWEException {
        JWE jwe = new JWE();
        jwe.getKeyStorage().setDecryptionKey(privateKey);
        jwe.verifyAndDecodeJwe(encryptedMessage);
        return new String(jwe.getContent(), StandardCharsets.UTF_8);
    }

    /**
     * Converts a private key to a flat Base64 string (no headers, no newlines).
     */
    public static String toBase64String(ECPrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    /**
     * Restores an ECPrivateKey from a flat Base64 string.
     */
    public static ECPrivateKey privateKeyFromBase64(String base64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64.trim());
            KeyFactory kf = KeyFactory.getInstance(KeyType.EC);
            return (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Failed to restore private key from Base64", e);
        }
    }

    public record EphemeralKey(ECPrivateKey privateKey, JWK publicKey) {}
}
