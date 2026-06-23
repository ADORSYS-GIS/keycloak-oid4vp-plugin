package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.mdoc.DeviceAuth;
import com.authlete.mdoc.DeviceKeyInfo;
import com.authlete.mdoc.DeviceNameSpaces;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;

import java.util.Map;

public class MdocDeviceSigned {

    private static final String KEY_DEVICE_NAME_SPACES = "nameSpaces";
    private static final String KEY_DEVICE_AUTH = "deviceAuth";
    private static final String KEY_DEVICE_KEY_INFO = "deviceKeyInfo";

    private final CBORPairList deviceSignedPairs;
    private final CBORItem rawDeviceNameSpaces;
    private final CBORItem rawDeviceAuth;

    public MdocDeviceSigned(CBORPairList deviceSignedPairs, CBORItem rawDeviceNameSpaces, CBORItem rawDeviceAuth) {
        this.deviceSignedPairs = deviceSignedPairs;
        this.rawDeviceNameSpaces = rawDeviceNameSpaces;
        this.rawDeviceAuth = rawDeviceAuth;
    }

    @SuppressWarnings("unchecked")
    public static MdocDeviceSigned parse(byte[] cborData) {
        try {
            CBORItem item = new CBORDecoder(cborData).next();
            return parse(item);
        } catch (java.io.IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static MdocDeviceSigned parse(CBORItem item) {
        CBORPairList pairs = (CBORPairList) item;
        CBORItem rawDeviceNameSpaces = extractRawField(pairs, KEY_DEVICE_NAME_SPACES);
        CBORItem rawDeviceAuth = extractRawField(pairs, KEY_DEVICE_AUTH);
        return new MdocDeviceSigned(pairs, rawDeviceNameSpaces, rawDeviceAuth);
    }

    private static CBORItem extractRawField(CBORPairList pairs, String key) {
        CBORPair pair = pairs.findByKey(key);
        if (pair != null) {
            return pair.getValue();
        }
        return null;
    }

    public CBORPairList getDeviceSignedPairs() {
        return deviceSignedPairs;
    }

    public DeviceNameSpaces getDeviceNameSpaces() {
        CBORItem item = extractRawField(deviceSignedPairs, KEY_DEVICE_NAME_SPACES);
        if (item instanceof DeviceNameSpaces dns) {
            return dns;
        }
        return null;
    }

    public DeviceAuth getDeviceAuth() {
        CBORItem item = extractRawField(deviceSignedPairs, KEY_DEVICE_AUTH);
        if (item instanceof DeviceAuth da) {
            return da;
        }
        return null;
    }

    public DeviceKeyInfo getDeviceKeyInfo() {
        CBORItem item = extractRawField(deviceSignedPairs, KEY_DEVICE_KEY_INFO);
        if (item instanceof DeviceKeyInfo dki) {
            return dki;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public Map<Object, Object> getDeviceNameSpacesAsMap() {
        CBORItem item = rawDeviceNameSpaces;
        if (item instanceof CBORPairList pairList) {
            return pairList.parse();
        }
        return null;
    }

    public CBORItem getRawDeviceNameSpaces() {
        return rawDeviceNameSpaces;
    }

    public CBORItem getRawDeviceAuth() {
        return rawDeviceAuth;
    }
}
