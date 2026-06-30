package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_DEVICE_SIGNATURE;
import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_ISSUER_AUTH;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSESign1;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class CborUtil {

    public static final int CBOR_TAG_EMBEDDED = 24;

    /**
     * Deeply unwrap CBORItem tree for convenience.
     */
    public static CBORItem unwrap(CBORItem item) {
        return unwrap(item, null, null);
    }

    /**
     * Deeply unwrap CBORItem tree for convenience.
     *
     * @param item      Root of CBOR tree to unwrap
     * @param key       Optional. Pair key associated with `item` in case it was a value to a CBORPair
     * @param tagNumber Optional. Tag number associated with `item` in case it was content of a CBORTaggedItem
     */
    private static CBORItem unwrap(CBORItem item, String key, Number tagNumber) {
        return switch (item) {
            // Always untag tagged items
            case CBORTaggedItem tagged -> unwrap(tagged.getTagContent(), null, tagged.getTagNumber());

            // Always attempt to unwrap byte arrays
            case CBORByteArray byteArray -> {
                try {
                    // Treat as CBOR and decode to unwrap
                    byte[] nestedBytes = byteArray.getValue();
                    CBORItem decodedInnerItem = new CBORDecoder(nestedBytes).next();

                    if (decodedInnerItem == null
                            || !numericEquals(CBOR_TAG_EMBEDDED, tagNumber)
                                    && !(decodedInnerItem instanceof CBORTaggedItem taggedItem
                                            && numericEquals(CBOR_TAG_EMBEDDED, taggedItem.getTagNumber()))) {
                        yield byteArray;
                    }

                    // Continue unwrapping in case there are nested unwrapped values
                    yield unwrap(decodedInnerItem);
                } catch (IOException e) {
                    yield byteArray;
                }
            }

            // Recursively traverse Maps / PairLists
            case CBORPairList cborPairList -> {
                List<CBORPair> unwrappedPairs = new ArrayList<>();
                for (CBORPair pair : cborPairList.getPairs()) {
                    // Keys are almost always strings/integers, but we unwrap values recursively
                    CBORItem unwrappedValue = unwrap(pair.getValue(), asString(pair.getKey()), null);
                    unwrappedPairs.add(new CBORPair(pair.getKey(), unwrappedValue));
                }
                yield new CBORPairList(unwrappedPairs);
            }

            // Recursively traverse Lists / Arrays
            case CBORItemList cborList -> {
                boolean likelyCoseArray =
                        List.of(L_ISSUER_AUTH, L_DEVICE_SIGNATURE).contains(key)
                                && cborList.getItems().size() == 4;

                List<CBORItem> unwrappedItems = new ArrayList<>();
                for (CBORItem subItem : cborList.getItems()) {
                    // Force unwrapping for first three entries of known COSE_Sign1 arrays
                    Number forceUnwrapping = likelyCoseArray && unwrappedItems.size() < 3 ? CBOR_TAG_EMBEDDED : null;
                    unwrappedItems.add(unwrap(subItem, null, forceUnwrapping));
                }

                yield new CBORItemList(unwrappedItems);
            }

            // Return primitives (Strings, Integers, Booleans, normal ByteArrays) as-is
            default -> item;
        };
    }

    /**
     * Extracts X5C chain from COSESign1.
     */
    public static List<X509Certificate> extractX509Chain(COSESign1 sign1) {
        if (sign1.getUnprotectedHeader() != null) {
            var chain = sign1.getUnprotectedHeader().getX5Chain();
            if (chain != null && !chain.isEmpty()) return chain;
        }

        if (sign1.getProtectedHeader() != null) {
            var chain = sign1.getProtectedHeader().getX5Chain();
            if (chain != null && !chain.isEmpty()) return chain;
        }

        return null;
    }

    /**
     * Reattach payload to COSESign1 with detached payload.
     */
    public static COSESign1 undetachCOSESign1(COSESign1 sign1, CBORTaggedItem payload) {
        return new COSESign1(
                sign1.getProtectedHeader(),
                sign1.getUnprotectedHeader(),
                new CBORByteArray(payload.encode()),
                sign1.getSignature());
    }

    /**
     * Wrap bytes into embedded CBOR
     */
    public static CBORTaggedItem wrap(byte[] content) {
        return new CBORTaggedItem(CborUtil.CBOR_TAG_EMBEDDED, new CBORByteArray(content));
    }

    /**
     * Convert CBOR item to string, avoiding quoted string.
     */
    public static String asString(CBORItem item) {
        if (item instanceof CBORString s) {
            return s.getValue();
        }

        return item.toString();
    }

    /**
     * Safe equality check with type Number.
     */
    public static boolean numericEquals(long value, Number n) {
        return n != null && n.longValue() == value;
    }
}
