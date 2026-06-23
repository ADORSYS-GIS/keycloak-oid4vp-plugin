package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORParser;
import com.networknt.schema.Schema;
import com.networknt.schema.SchemaRegistry;
import com.networknt.schema.dialect.Dialects;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.util.CBORUtil;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

public class MdocParser {

    private static final Schema schema;

    static {
        try {
            InputStream schemaStream = MdocParser.class.getResourceAsStream("/mdoc/mdoc-device-response-schema.json");

            if (schemaStream == null) {
                throw new IllegalStateException("Schema file not found in classpath.");
            }

            SchemaRegistry schemaRegistry = SchemaRegistry.withDialect(Dialects.getDraft7());
            schema = schemaRegistry.getSchema(schemaStream);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to initialize MDOC JSON Schema", e);
        }
    }

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

        CBORItem root;

        try {
            root = new CBORDecoder(cborData).next();
        } catch (IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }

        if (!(root instanceof CBORPairList pairs)) {
            throw new MdocEncodingException("CBOR data is not a CBOR map");
        }

        try {
            System.out.println(root.prettify());
            CBORItem unwrapped = CBORUtil.unwrap(root);
            Object node = new CBORParser(unwrapped.encode()).next();
            System.out.println(JsonSerialization.valueAsPrettyString(node));
            var errors = schema.validate(JsonSerialization.mapper.valueToTree(node));
            if (!errors.isEmpty()) {
                throw new MdocEncodingException("mDoc fails schema validation: " + errors);
            }
        } catch (IOException | IllegalArgumentException e) {
            throw new MdocEncodingException("Invalid mDoc device response", e);
        }

        return pairs;
    }
}
