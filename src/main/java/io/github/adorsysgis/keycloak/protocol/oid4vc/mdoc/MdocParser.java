package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPairList;
import java.io.IOException;
import java.util.Base64;
import org.keycloak.utils.StringUtil;

public class MdocParser {

    private MdocParser() {}

    public static CBORPairList parseBase64Url(String base64Url) throws MdocEncodingException {
        if (StringUtil.isBlank(base64Url)) {
            throw new MdocEncodingException("Input string is null or blank");
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(base64Url.trim());
            return parse(decoded);
        } catch (IllegalArgumentException e) {
            throw new MdocEncodingException("Invalid Base64url encoding", e);
        }
    }

    public static CBORPairList parse(byte[] cborData) throws MdocEncodingException {
        if (cborData == null || cborData.length == 0) {
            throw new MdocEncodingException("Input bytes are null or empty");
        }
        try {
            CBORItem item = new CBORDecoder(cborData).next();
            if (item instanceof CBORPairList pairs) {
                return pairs;
            }
            throw new MdocEncodingException("CBOR data is not a CBOR map");
        } catch (IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }
    }
}
