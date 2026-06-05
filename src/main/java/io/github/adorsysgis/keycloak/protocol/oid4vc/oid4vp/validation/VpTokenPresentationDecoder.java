package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Decodes {@code vp_token} presentation entries when wallets return Base64URL-encoded SD-JWT strings.
 */
public final class VpTokenPresentationDecoder {

    private VpTokenPresentationDecoder() {}

    public static String decodeIfBase64Url(String encodedPresentation) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encodedPresentation);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return encodedPresentation;
        }
    }
}
