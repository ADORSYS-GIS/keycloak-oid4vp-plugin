package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class MdocDeviceResponse {

    private static final String KEY_VERSION = "version";
    private static final String KEY_DOCUMENTS = "documents";
    private static final String KEY_STATUS = "status";

    private final CBORPairList deviceResponsePairs;
    private final String version;
    private final List<MdocDocument> documents;
    private final int status;

    public MdocDeviceResponse(
            CBORPairList deviceResponsePairs, String version, List<MdocDocument> documents, int status) {
        this.deviceResponsePairs = deviceResponsePairs;
        this.version = version;
        this.documents = documents;
        this.status = status;
    }

    public static MdocDeviceResponse parse(byte[] cborData) throws MdocEncodingException {
        try {
            CBORItem item = new CBORDecoder(cborData).next();
            return parse(item);
        } catch (IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }
    }

    public static MdocDeviceResponse parse(CBORItem item) {
        CBORPairList pairs = (CBORPairList) item;
        String version = extractStringField(pairs, KEY_VERSION);
        int status = extractIntField(pairs, KEY_STATUS);
        List<MdocDocument> documents = extractDocuments(pairs);
        return new MdocDeviceResponse(pairs, version, documents, status);
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
        if (item != null) {
            return item.toString();
        }
        return null;
    }

    private static int extractIntField(CBORPairList pairs, String key) {
        CBORItem item = extractRawField(pairs, key);
        if (item != null) {
            try {
                return Integer.parseInt(item.toString());
            } catch (NumberFormatException e) {
                return -1;
            }
        }
        return -1;
    }

    private static List<MdocDocument> extractDocuments(CBORPairList pairs) {
        CBORItem item = extractRawField(pairs, KEY_DOCUMENTS);
        List<MdocDocument> docs = new ArrayList<>();
        if (item instanceof CBORItemList itemList) {
            for (CBORItem docItem : itemList.getItems()) {
                try {
                    docs.add(MdocDocument.parse(docItem));
                } catch (Exception e) {
                }
            }
        }
        return docs;
    }

    public CBORPairList getDeviceResponsePairs() {
        return deviceResponsePairs;
    }

    public String getVersion() {
        return version;
    }

    public List<MdocDocument> getDocuments() {
        return documents;
    }

    public int getStatus() {
        return status;
    }

    public boolean isSuccess() {
        return status == 0;
    }

    public String getStatusMessage() {
        return switch (status) {
            case 0 -> "Success";
            case 1 -> "Internal error";
            case 2 -> "Session expired";
            case 3 -> "Device retrieval requested";
            default -> "Unknown status: " + status;
        };
    }
}
