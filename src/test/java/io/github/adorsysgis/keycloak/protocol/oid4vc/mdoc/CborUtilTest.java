package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import java.util.List;
import org.junit.jupiter.api.Test;

class CborUtilTest {

    @Test
    void shouldKeepUntaggedByteArraysOpaque() {
        CBORByteArray opaqueBytes = new CBORByteArray(new CBORString("parseable-but-opaque").encode());
        CBORPairList root = new CBORPairList(new CBORPair(new CBORString("digest"), opaqueBytes));

        CBORPairList unwrapped = (CBORPairList) CborUtil.unwrap(root);

        assertInstanceOf(CBORByteArray.class, unwrapped.findByKey("digest").getValue());
    }

    @Test
    void shouldDecodeExplicitEmbeddedCbor() {
        CBORTaggedItem embedded = new CBORTaggedItem(
                CborUtil.CBOR_TAG_EMBEDDED, new CBORByteArray(new CBORString("embedded").encode()));

        assertEquals("embedded", ((CBORString) CborUtil.unwrap(embedded)).getValue());
    }

    @Test
    void shouldDecodeKnownCoseByteStringFields() {
        CBORByteArray protectedHeader = new CBORByteArray(new CBORPairList(List.of()).encode());
        CBORByteArray payload = new CBORByteArray(new CBORString("payload").encode());
        CBORByteArray signature = new CBORByteArray(new byte[] {1, 2, 3});
        CBORItemList coseSign1 = new CBORItemList(
                protectedHeader, new CBORPairList(List.of()), payload, signature);
        CBORPairList root = new CBORPairList(new CBORPair(new CBORString(MdocConstants.L_ISSUER_AUTH), coseSign1));

        CBORItemList unwrappedCoseSign1 =
                (CBORItemList) ((CBORPairList) CborUtil.unwrap(root)).findByKey(MdocConstants.L_ISSUER_AUTH).getValue();

        assertInstanceOf(CBORPairList.class, unwrappedCoseSign1.getItems().get(0));
        assertInstanceOf(CBORString.class, unwrappedCoseSign1.getItems().get(2));
        assertInstanceOf(CBORByteArray.class, unwrappedCoseSign1.getItems().get(3));
    }
}
