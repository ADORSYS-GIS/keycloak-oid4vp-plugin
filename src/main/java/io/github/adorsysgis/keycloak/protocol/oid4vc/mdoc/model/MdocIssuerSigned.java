package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cose.COSEMessage;
import com.authlete.cose.COSESign1;
import com.authlete.cwt.CWT;
import com.authlete.mdoc.IssuerNameSpaces;
import com.authlete.mdoc.MobileSecurityObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;

import java.util.Map;

public class MdocIssuerSigned {

    private static final String KEY_NAME_SPACES = "nameSpaces";
    private static final String KEY_ISSUER_AUTH = "issuerAuth";

    private final CBORPairList issuerSignedPairs;
    private final CBORItem rawIssuerAuth;
    private final MobileSecurityObject mso;

    public MdocIssuerSigned(CBORPairList issuerSignedPairs, CBORItem rawIssuerAuth, MobileSecurityObject mso) {
        this.issuerSignedPairs = issuerSignedPairs;
        this.rawIssuerAuth = rawIssuerAuth;
        this.mso = mso;
    }

    @SuppressWarnings("unchecked")
    public static MdocIssuerSigned parse(byte[] cborData) {
        try {
            CBORItem item = new CBORDecoder(cborData).next();
            return parse(item);
        } catch (java.io.IOException e) {
            throw new MdocEncodingException("Failed to parse CBOR data", e);
        }
    }

    @SuppressWarnings("unchecked")
    public static MdocIssuerSigned parse(CBORItem item) {
        CBORPairList pairs = (CBORPairList) item;
        CBORItem rawIssuerAuth = extractRawField(pairs, KEY_ISSUER_AUTH);
        MobileSecurityObject mso = extractMSO(rawIssuerAuth);
        return new MdocIssuerSigned(pairs, rawIssuerAuth, mso);
    }

    private static CBORItem extractRawField(CBORPairList pairs, String key) {
        CBORPair pair = pairs.findByKey(key);
        if (pair != null) {
            return pair.getValue();
        }
        return null;
    }

    private static MobileSecurityObject extractMSO(CBORItem issuerAuthItem) {
        try {
            if (issuerAuthItem instanceof CWT cwt) {
                COSEMessage message = cwt.getMessage();
                if (message instanceof COSESign1 sign1) {
                    CBORItem payload = sign1.getPayload();
                    if (payload instanceof CBORByteArray byteArray) {
                        byte[] payloadBytes = byteArray.getValue();
                        if (payloadBytes != null && payloadBytes.length > 0) {
                            CBORItem msoItem = new CBORDecoder(payloadBytes).next();
                            if (msoItem instanceof MobileSecurityObject mso) {
                                return mso;
                            }
                        }
                    }
                }
            } else if (issuerAuthItem instanceof COSESign1 sign1) {
                CBORItem payload = sign1.getPayload();
                if (payload instanceof CBORByteArray byteArray) {
                    byte[] payloadBytes = byteArray.getValue();
                    if (payloadBytes != null && payloadBytes.length > 0) {
                        CBORItem msoItem = new CBORDecoder(payloadBytes).next();
                        if (msoItem instanceof MobileSecurityObject mso) {
                            return mso;
                        }
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    public CBORPairList getIssuerSignedPairs() {
        return issuerSignedPairs;
    }

    public IssuerNameSpaces getIssuerNameSpaces() {
        CBORItem item = extractRawField(issuerSignedPairs, KEY_NAME_SPACES);
        if (item instanceof IssuerNameSpaces ins) {
            return ins;
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    public Map<Object, Object> getIssuerNameSpacesAsMap() {
        IssuerNameSpaces ns = getIssuerNameSpaces();
        if (ns != null) {
            return ns.parse();
        }
        return null;
    }

    public MobileSecurityObject getMobileSecurityObject() {
        return mso;
    }

    public CBORItem getRawIssuerAuth() {
        return rawIssuerAuth;
    }

    public String getDocType() {
        if (mso != null) {
            String result = extractStringFromMSO(mso, "docType");
            if (result != null) {
                return result;
            }
        }
        IssuerNameSpaces ns = getIssuerNameSpaces();
        if (ns != null) {
            String result = extractStringFromNamespace(ns, "docType");
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    private String extractStringFromMSO(CBORPairList msoPairs, String key) {
        CBORPair pair = msoPairs.findByKey(key);
        if (pair != null) {
            CBORItem value = pair.getValue();
            if (value instanceof CBORString s) {
                return s.getValue();
            }
            Map<Object, Object> map = msoPairs.parse();
            Object val = map.get(key);
            if (val instanceof String str) {
                return str;
            }
        }
        return null;
    }

    private String extractStringFromNamespace(IssuerNameSpaces ns, String key) {
        CBORPair pair = ns.findByKey(key);
        if (pair != null) {
            CBORItem value = pair.getValue();
            if (value instanceof CBORString s) {
                return s.getValue();
            }
            Map<Object, Object> map = ns.parse();
            Object val = map.get(key);
            if (val instanceof String str) {
                return str;
            }
        }
        return null;
    }

    public String getDigestAlgorithm() {
        if (mso != null) {
            return extractStringFromMSO(mso, "digestAlgorithm");
        }
        return null;
    }

    public String getVersion() {
        if (mso != null) {
            return extractStringFromMSO(mso, "version");
        }
        return null;
    }
}
