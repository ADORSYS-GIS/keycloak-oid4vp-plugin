package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.validation;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.keycloak.utils.StringUtil;

/**
 * Normalizes presentation encodings returned in a {@code vp_token}.
 *
 * <p>Wallets are expected to return the SD-JWT verifiable presentation in its on-the-wire compact form:
 * an issuer-signed JWT, optional disclosures, and an optional key-binding JWT separated by {@code ~}
 * (see SD-JWT / SD-JWT VC specs). That string already contains {@code .} segment separators and must
 * not be base64url-decoded as a whole.
 *
 * <p>Some wallet implementations instead return the same compact presentation wrapped as a single
 * base64url-encoded UTF-8 string (no {@code .} or {@code ~} in the wrapper). This decoder detects
 * the compact SD-JWT/JWT shape first and only attempts base64url decoding when the value is not
 * already a presentation.
 */
final class VpTokenPresentationDecoder {

    private VpTokenPresentationDecoder() {}

    /**
     * Returns a compact SD-JWT presentation string, accepting either raw or base64url-wrapped input.
     */
    static String decodeIfBase64Url(String input) {
        if (StringUtil.isBlank(input)) {
            return input;
        }

        String trimmed = input.trim();
        if (looksLikeSdJwtPresentation(trimmed)) {
            return trimmed;
        }

        try {
            byte[] decoded = Base64.getUrlDecoder().decode(trimmed);
            String decodedPresentation = new String(decoded, StandardCharsets.UTF_8);
            if (looksLikeSdJwtPresentation(decodedPresentation)) {
                return decodedPresentation;
            }
        } catch (IllegalArgumentException ignored) {
            // Not a base64url wrapper; return the original value for downstream parse errors.
        }

        return trimmed;
    }

    /**
     * Detects compact SD-JWT VP strings ({@code <JWT>~[<disclosures>~]<KB-JWT>}) and plain JWTs.
     */
    static boolean looksLikeSdJwtPresentation(String value) {
        if (StringUtil.isBlank(value)) {
            return false;
        }
        if (value.contains("~")) {
            return looksLikeCompactJwt(value.substring(0, value.indexOf('~')));
        }
        return looksLikeCompactJwt(value);
    }

    private static boolean looksLikeCompactJwt(String value) {
        String[] parts = value.split("\\.");
        return parts.length >= 3 && !parts[0].isEmpty() && !parts[1].isEmpty() && !parts[2].isEmpty();
    }
}
