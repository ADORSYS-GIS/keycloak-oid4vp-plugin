package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Normalizes presentation encodings returned in a {@code vp_token}.
 */
final class VpTokenPresentationDecoder {

    private VpTokenPresentationDecoder() {}

    static String decodeIfBase64Url(String input) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(input);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return input;
        }
    }
}
