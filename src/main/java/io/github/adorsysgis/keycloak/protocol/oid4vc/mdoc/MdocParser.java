package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocDeviceResponse;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocDocument;

import java.util.Base64;

public class MdocParser {

    private MdocParser() {}

    public static MdocDeviceResponse parseBase64Url(String base64Url) throws MdocEncodingException {
        if (base64Url == null || base64Url.isBlank()) {
            throw new MdocEncodingException("Input string is null or blank");
        }
        try {
            byte[] decoded = base64UrlDecoder().decode(base64Url.trim());
            return MdocDeviceResponse.parse(decoded);
        } catch (IllegalArgumentException e) {
            throw new MdocEncodingException("Invalid Base64url encoding", e);
        }
    }

    public static MdocDeviceResponse parse(byte[] cborData) throws MdocEncodingException {
        if (cborData == null || cborData.length == 0) {
            throw new MdocEncodingException("Input bytes are null or empty");
        }
        return MdocDeviceResponse.parse(cborData);
    }

    public static MdocDocument parseDocumentBase64Url(String base64Url) throws MdocEncodingException {
        if (base64Url == null || base64Url.isBlank()) {
            throw new MdocEncodingException("Input string is null or blank");
        }
        try {
            byte[] decoded = base64UrlDecoder().decode(base64Url.trim());
            return MdocDocument.parse(decoded);
        } catch (IllegalArgumentException e) {
            throw new MdocEncodingException("Invalid Base64url encoding", e);
        }
    }

    private static Base64.Decoder base64UrlDecoder() {
        return Base64.getUrlDecoder();
    }
}
