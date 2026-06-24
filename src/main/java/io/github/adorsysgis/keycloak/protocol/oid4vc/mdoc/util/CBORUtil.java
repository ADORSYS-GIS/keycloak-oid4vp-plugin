package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.util;

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
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class CBORUtil {

    /**
     * Deeply unwrap CBORItem tree for convenience.
     */
    public static CBORItem unwrap(CBORItem item) {
        return unwrap(item, null, null);
    }

    /**
     * Deeply unwrap CBORItem tree for convenience.
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
                            || !numericEquals(24, tagNumber)
                                    && !(decodedInnerItem instanceof CBORTaggedItem taggedItem
                                            && numericEquals(24, taggedItem.getTagNumber()))) {
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
                    Number forceUnwrapping = likelyCoseArray && unwrappedItems.size() < 3 ? 24 : null;
                    unwrappedItems.add(unwrap(subItem, null, forceUnwrapping));
                }

                yield new CBORItemList(unwrappedItems);
            }

            // Return primitives (Strings, Integers, Booleans, normal ByteArrays) as-is
            default -> item;
        };
    }

    @SuppressWarnings("SameParameterValue")
    private static boolean numericEquals(long value, Number n) {
        return n != null && n.longValue() == value;
    }

    private static String asString(CBORItem item) {
        if (item instanceof CBORString s) {
            return s.getValue();
        }

        return item.toString();
    }
}
