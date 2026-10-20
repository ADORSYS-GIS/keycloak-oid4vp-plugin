package io.github.adorsysgis.keycloak.protocol.oid4vc.patch.utils;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Helpers for decrypting and re-encrypting a JWE-encrypted OID4VCI Credential Request (§10).
 * <p>
 * The decryption and key-resolution logic mirrors the private operations in the upstream
 * {@code OID4VCIssuerEndpoint} ({@code isCompactJwePayload} and {@code decryptCredentialRequest}):
 * a compact JWE is decrypted with the realm encryption key referenced by the protected-header
 * {@code kid}. The re-encryption helper has no upstream counterpart (upstream only decrypts); it is
 * patch-specific so a patched plaintext request can be sealed again with the same key material
 * without disturbing the upstream endpoint's request-encryption validation.
 * </p>
 */
public final class EncryptedPayloadUtils {

    private EncryptedPayloadUtils() {}

    /**
     * Whether the payload is a compact JWE (as opposed to a plaintext JSON Credential Request).
     */
    public static boolean isCompactJwe(String payload) {
        try {
            return new JWE(payload).getHeader() != null;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    /**
     * Decrypts a compact JWE credential request with the realm encryption key referenced by the
     * protected-header {@code kid}.
     *
     * @return the decrypted {@link JWE} whose {@link JWE#getContent()} holds the plaintext payload
     */
    public static JWE decrypt(KeycloakSession session, String jweString) throws Exception {
        JWE jwe = new JWE(jweString);
        JWEHeader header = (JWEHeader) jwe.getHeader();
        KeyWrapper keyWrapper = resolveEncKey(session, header.getKeyId());
        jwe.getKeyStorage().setDecryptionKey(keyWrapper.getPrivateKey());
        jwe.verifyAndDecodeJwe();
        return jwe;
    }

    /**
     * Re-encrypts a plaintext payload to the same realm encryption key (same {@code kid}) reusing the
     * original protected header, so the wallet's original {@code alg}/{@code enc} are preserved and
     * the upstream endpoint can decrypt it again.
     */
    public static String reEncrypt(KeycloakSession session, String plaintext, JWE original) throws Exception {
        JWEHeader header = (JWEHeader) original.getHeader();
        KeyWrapper keyWrapper = resolveEncKey(session, header.getKeyId());
        JWE jwe = new JWE().header(header).content(plaintext.getBytes(StandardCharsets.UTF_8));
        jwe.getKeyStorage().setEncryptionKey(keyWrapper.getPublicKey());
        return jwe.encodeJwe();
    }

    private static KeyWrapper resolveEncKey(KeycloakSession session, String kid) {
        KeyManager keyManager = session.keys();
        RealmModel realm = session.getContext().getRealm();

        List<KeyWrapper> matching = keyManager
                .getKeysStream(realm)
                .filter(key -> KeyUse.ENC.equals(key.getUse()) && kid.equals(key.getKid()))
                .toList();

        if (matching.isEmpty()) {
            throw new IllegalStateException("No realm encryption key found for kid: " + kid);
        }

        if (matching.size() > 1) {
            throw new IllegalStateException("Multiple realm encryption keys found for kid: " + kid);
        }

        return matching.getFirst();
    }
}
