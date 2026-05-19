package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.service.VerifierDiscoveryService;
import java.util.List;
import java.util.Optional;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEConstants;
import org.keycloak.jose.jwe.JWEHeader;
import org.keycloak.jose.jwk.JWK;

/**
 * Validates the protected header of a wallet {@code direct_post.jwt} JWE against verifier policy and the
 * {@code client_metadata.jwks} published in the signed authorization request (OpenID for Verifiable Presentations 1.0).
 */
public final class AuthorizationResponseJweValidator {

    private AuthorizationResponseJweValidator() {}

    /**
     * Ensures the encrypted response uses allowed algorithms and a {@code kid} that matches keys the verifier
     * advertised in the request object.
     *
     * @throws IllegalArgumentException with a human-readable message when validation fails
     */
    public static void validate(String encryptedResponse, AuthorizationContext authorizationContext) {
        final JWEHeader header;
        try {
            JWE parsed = new JWE(encryptedResponse);
            header = (JWEHeader) parsed.getHeader();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Encrypted response is not a compact JWE", e);
        }

        if (header == null) {
            throw new IllegalArgumentException(
                    "The JWE protected header could not be read from the encrypted response.");
        }

        String alg = header.getAlgorithm();
        String enc = header.getEncryptionAlgorithm();
        String kid = header.getKeyId();

        if (alg == null || enc == null) {
            throw new IllegalArgumentException(
                    "The JWE protected header is missing required parameters `alg` and/or `enc`.");
        }

        var clientMetadata = authorizationContext.getRequestObject().getClientMetadata();
        if (!List.of(JWEConstants.ECDH_ES).contains(alg)) {
            throw new IllegalArgumentException(String.format(
                    "Unsupported JWE key management algorithm `%s` (this verifier supports ECDH-ES only).", alg));
        }

        List<String> allowedEnc = resolveAllowedEnc(clientMetadata);
        if (!allowedEnc.contains(enc)) {
            throw new IllegalArgumentException(String.format(
                    "Unsupported JWE content encryption algorithm `%s`. "
                            + "Allowed values are those advertised in `encrypted_response_enc_values_supported` "
                            + "or the verifier default set (%s).",
                    enc, String.join(", ", VerifierDiscoveryService.SUPPORTED_ENC_ALGS)));
        }

        // For direct_post.jwt the verifier advertises a single ephemeral key in the signed request object;
        // kid binding is validated against that JWKS entry (OpenID4VP 1.0 §8.3).
        String expectedKid = resolveAdvertisedEncryptionKid(authorizationContext);
        if (kid == null) {
            throw new IllegalArgumentException(
                    "The JWE protected header must include `kid` so the ciphertext can be matched to an advertised "
                            + "encryption key.");
        }
        if (expectedKid != null && !expectedKid.equals(kid)) {
            throw new IllegalArgumentException(String.format(
                    "JWE `kid` (`%s`) does not match the encryption key advertised for this authorization "
                            + "request (`%s`).",
                    kid, expectedKid));
        }

        JWK selectedKey = resolveEncryptionJwkFromRequestMetadata(clientMetadata, kid);

        String keyAlg = selectedKey.getAlgorithm();
        if (keyAlg != null && !keyAlg.equals(alg)) {
            throw new IllegalArgumentException(String.format(
                    "JWE `alg` (`%s`) does not match the `alg` parameter declared on the advertised JWK (`%s`).",
                    alg, keyAlg));
        }
    }

    /**
     * When this session expects an encrypted response, returns the {@code kid} of the sole key published
     * under {@code client_metadata.jwks} in the signed authorization request.
     */
    private static String resolveAdvertisedEncryptionKid(AuthorizationContext authorizationContext) {
        String ephemeralKey = authorizationContext.getEphemeralKey();
        if (ephemeralKey == null || ephemeralKey.isBlank()) {
            return null;
        }
        var requestObject = authorizationContext.getRequestObject();
        if (requestObject == null) {
            return null;
        }
        ClientMetadata clientMetadata = requestObject.getClientMetadata();
        if (clientMetadata == null || clientMetadata.getJwks() == null) {
            return null;
        }
        JWK[] keys = clientMetadata.getJwks().getKeys();
        if (keys == null || keys.length != 1) {
            return null;
        }
        return keys[0].getKeyId();
    }

    private static List<String> resolveAllowedEnc(ClientMetadata clientMetadata) {
        return Optional.ofNullable(clientMetadata)
                .map(ClientMetadata::getEncryptedResponseEncValuesSupported)
                .filter(list -> !list.isEmpty())
                .orElse(VerifierDiscoveryService.SUPPORTED_ENC_ALGS);
    }

    private static JWK resolveEncryptionJwkFromRequestMetadata(ClientMetadata clientMetadata, String jweKeyId) {
        if (clientMetadata == null || clientMetadata.getJwks() == null) {
            throw new IllegalArgumentException(
                    "No encryption keys were published under `client_metadata.jwks` in the signed authorization "
                            + "request.");
        }
        JWK[] keys = clientMetadata.getJwks().getKeys();
        if (keys == null || keys.length == 0) {
            throw new IllegalArgumentException(
                    "No encryption keys were published under `client_metadata.jwks` in the signed authorization "
                            + "request.");
        }
        for (JWK key : keys) {
            if (jweKeyId.equals(key.getKeyId())) {
                return key;
            }
        }
        throw new IllegalArgumentException(String.format(
                "JWE `kid` `%s` does not match any key published under `client_metadata.jwks` for this "
                        + "authorization request.",
                jweKeyId));
    }
}
