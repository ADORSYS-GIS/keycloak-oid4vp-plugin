package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;

import java.util.Map;

public class MdocDocument {

    private static final String KEY_DOC_TYPE = "docType";
    private static final String KEY_ISSUER_SIGNED = "issuerSigned";
    private static final String KEY_DEVICE_SIGNED = "deviceSigned";

    private final CBORPairList documentPairs;
    private final String docType;
    private final MdocIssuerSigned issuerSigned;
    private final MdocDeviceSigned deviceSigned;

    public MdocDocument(
            CBORPairList documentPairs, String docType, MdocIssuerSigned issuerSigned, MdocDeviceSigned deviceSigned) {
        this.documentPairs = documentPairs;
        this.docType = docType;
        this.issuerSigned = issuerSigned;
        this.deviceSigned = deviceSigned;
    }

    public static MdocDocument parse(byte[] cborData) {
        try {
            CBORItem item = new CBORDecoder(cborData).next();
            return parse(item);
        } catch (java.io.IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }
    }

    public static MdocDocument parse(CBORItem item) {
        CBORPairList pairs = (CBORPairList) item;
        String docType = extractStringField(pairs, KEY_DOC_TYPE);
        CBORItem issuerSignedItem = extractRawField(pairs, KEY_ISSUER_SIGNED);
        CBORItem deviceSignedItem = extractRawField(pairs, KEY_DEVICE_SIGNED);
        MdocIssuerSigned issuerSigned = MdocIssuerSigned.parse(issuerSignedItem);
        MdocDeviceSigned deviceSigned = MdocDeviceSigned.parse(deviceSignedItem);
        return new MdocDocument(pairs, docType, issuerSigned, deviceSigned);
    }

    private static CBORItem extractRawField(CBORPairList pairs, String key) {
        CBORPair pair = pairs.findByKey(key);
        if (pair != null) {
            return pair.getValue();
        }
        return null;
    }

    private static String extractStringField(CBORPairList pairs, String key) {
        CBORItem item = extractRawField(pairs, key);
        if (item instanceof CBORString cborString) {
            return cborString.getValue();
        }
        Map<Object, Object> map = pairs.parse();
        Object value = map.get(key);
        if (value instanceof String s) {
            return s;
        }
        return item != null ? item.toString() : null;
    }

    public CBORPairList getDocumentPairs() {
        return documentPairs;
    }

    public String getDocType() {
        return docType;
    }

    public MdocIssuerSigned getIssuerSigned() {
        return issuerSigned;
    }

    public MdocDeviceSigned getDeviceSigned() {
        return deviceSigned;
    }
}
