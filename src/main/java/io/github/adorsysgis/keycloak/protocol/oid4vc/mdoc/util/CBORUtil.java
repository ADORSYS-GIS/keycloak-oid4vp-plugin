package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.util;

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
import java.util.HexFormat;
import java.util.List;

public class CBORUtil {

    /**
     * Deeply unwrap CBORItem tree for convenience.
     */
    public static CBORItem unwrap(CBORItem item) {
        return switch (item) {
            // Always untag tagged items
            case CBORTaggedItem tagged -> unwrap(tagged.getTagContent());

            // Always attempt to unwrap byte arrays
            case CBORByteArray byteArray -> {
                try {
                    // Treat as CBOR and decode to unwrap
                    byte[] nestedBytes = byteArray.getValue();
                    CBORItem decodedInnerItem = new CBORDecoder(nestedBytes).next();

                    // Convert to hexadecimal string if decoded item is neither a tagged item nor map
                    if (!(decodedInnerItem instanceof CBORTaggedItem) && !(decodedInnerItem instanceof CBORPairList)) {
                        String hex = HexFormat.of().formatHex(byteArray.getValue());
                        System.out.println("hex: " + hex);
                        yield new CBORString("hex:" + hex);
                    }

                    // Continue unwrapping in case there are nested unwrapped values
                    yield unwrap(decodedInnerItem);
                } catch (IOException e) {
                    String hex = HexFormat.of().formatHex(byteArray.getValue());
                    System.out.println("hex2: " + hex);
                    yield new CBORString("hex2:" + hex);
                }
            }

            // Recursively traverse Maps / PairLists
            case CBORPairList cborPairList -> {
                List<CBORPair> unwrappedPairs = new ArrayList<>();
                for (CBORPair pair : cborPairList.getPairs()) {
                    // Keys are almost always strings/integers, but we unwrap values recursively
                    CBORItem unwrappedValue = unwrap(pair.getValue());
                    unwrappedPairs.add(new CBORPair(pair.getKey(), unwrappedValue));
                }
                yield new CBORPairList(unwrappedPairs);
            }

            // Recursively traverse Lists / Arrays
            case CBORItemList cborList -> {
                List<CBORItem> unwrappedItems = new ArrayList<>();
                for (CBORItem subItem : cborList.getItems()) {
                    unwrappedItems.add(unwrap(subItem));
                }
                yield new CBORItemList(unwrappedItems);
            }

            // Return primitives (Strings, Integers, Booleans, normal ByteArrays) as-is
            default -> item;
        };
    }
}
