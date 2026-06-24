package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.mdoc.DeviceResponse;
import java.util.List;
import org.junit.jupiter.api.Test;

public class MdocParserTest extends MdocBaseTest {

    @Test
    void shouldParseBase64UrlEncodedDeviceResponse() throws Exception {
        DeviceResponse deviceResponse = buildDeviceResponse();
        String encoded = deviceResponse.encodeToBase64Url();

        CBORPairList parsed = MdocParser.parseBase64Url(encoded);
        assertEquals(encoded, parsed.encodeToBase64Url());
    }

    @Test
    void shouldParseRawBytesDeviceResponse() throws Exception {
        DeviceResponse deviceResponse = buildDeviceResponse();
        byte[] encoded = deviceResponse.encode();

        CBORPairList parsed = MdocParser.parse(encoded);
        assertArrayEquals(encoded, parsed.encode());
    }

    @Test
    void shouldValidateDeviceResponseStructure() throws Exception {
        DeviceResponse deviceResponse = buildDeviceResponse();
        String encoded = deviceResponse.encodeToBase64Url();

        CBORPairList parsed = MdocParser.parseBase64Url(encoded);

        CBORPair versionPair = parsed.findByKey("version");
        assertNotNull(versionPair);
        assertInstanceOf(CBORString.class, versionPair.getValue());
        assertEquals("1.0", ((CBORString) versionPair.getValue()).getValue());

        CBORPair statusPair = parsed.findByKey("status");
        assertNotNull(statusPair);
        assertInstanceOf(CBORInteger.class, statusPair.getValue());

        CBORPair documentsPair = parsed.findByKey("documents");
        assertNotNull(documentsPair);
        assertInstanceOf(CBORItemList.class, documentsPair.getValue());
        CBORItemList documents = (CBORItemList) documentsPair.getValue();
        assertEquals(1, documents.getItems().size());

        CBORItem docItem = documents.getItems().getFirst();
        assertInstanceOf(CBORPairList.class, docItem);
        CBORPairList doc = (CBORPairList) docItem;

        CBORPair docTypePair = doc.findByKey("docType");
        assertNotNull(docTypePair);
        assertInstanceOf(CBORString.class, docTypePair.getValue());
        assertEquals("com.example.doctype", ((CBORString) docTypePair.getValue()).getValue());

        CBORPair issuerSignedPair = doc.findByKey("issuerSigned");
        assertNotNull(issuerSignedPair);
        assertInstanceOf(CBORPairList.class, issuerSignedPair.getValue());
    }

    @Test
    void shouldRoundtripSpecSampleVector() throws Exception {
        String base64Url = readResource("/mdoc/spec-sample.txt");

        CBORPairList parsed = MdocParser.parseBase64Url(base64Url);
        String reEncoded = parsed.encodeToBase64Url();
        assertEquals(base64Url, reEncoded);
    }

    @Test
    void shouldParseAndValidateSpecSampleVector() throws Exception {
        String base64Url = readResource("/mdoc/spec-sample.txt");

        CBORPairList parsed = MdocParser.parseBase64Url(base64Url);
        assertNotNull(parsed);

        CBORPair versionPair = parsed.findByKey("version");
        assertNotNull(versionPair);
        assertInstanceOf(CBORString.class, versionPair.getValue());
        assertEquals("1.0", ((CBORString) versionPair.getValue()).getValue());

        CBORPair statusPair = parsed.findByKey("status");
        assertNotNull(statusPair);
        assertInstanceOf(CBORInteger.class, statusPair.getValue());

        CBORPair documentsPair = parsed.findByKey("documents");
        assertNotNull(documentsPair);
        assertInstanceOf(CBORItemList.class, documentsPair.getValue());

        CBORItemList documents = (CBORItemList) documentsPair.getValue();
        assertEquals(1, documents.getItems().size());

        CBORPairList doc = (CBORPairList) documents.getItems().getFirst();
        CBORPair docTypePair = doc.findByKey("docType");
        assertNotNull(docTypePair);
        assertInstanceOf(CBORString.class, docTypePair.getValue());
        assertEquals("org.iso.18013.5.1.mDL", ((CBORString) docTypePair.getValue()).getValue());

        CBORPair issuerSignedPair = doc.findByKey("issuerSigned");
        assertNotNull(issuerSignedPair);
        assertInstanceOf(CBORPairList.class, issuerSignedPair.getValue());

        CBORPair deviceSignedPair = doc.findByKey("deviceSigned");
        assertNotNull(deviceSignedPair);
        assertInstanceOf(CBORPairList.class, deviceSignedPair.getValue());
    }

    @Test
    void shouldRoundtripConformanceSampleVector() throws Exception {
        String base64Url = readResource("/mdoc/conformance-sample.txt");

        CBORPairList parsed = MdocParser.parseBase64Url(base64Url);
        String reEncoded = parsed.encodeToBase64Url();
        assertEquals(base64Url, reEncoded);
    }

    @Test
    void shouldThrowOnNullBase64Input() {
        MdocEncodingException ex = assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url(null));
        assertEquals("Input string is null or blank", ex.getMessage());
    }

    @Test
    void shouldThrowOnBlankBase64Input() {
        MdocEncodingException ex = assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url("   "));
        assertEquals("Input string is null or blank", ex.getMessage());
    }

    @Test
    void shouldThrowOnInvalidBase64Input() {
        MdocEncodingException ex =
                assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url("not-valid!!!"));
        assertEquals("Invalid Base64url encoding", ex.getMessage());
    }

    @Test
    void shouldThrowOnNullBytes() {
        MdocEncodingException ex = assertThrows(MdocEncodingException.class, () -> MdocParser.parse(null));
        assertEquals("Input bytes are null or empty", ex.getMessage());
    }

    @Test
    void shouldThrowOnEmptyBytes() {
        MdocEncodingException ex = assertThrows(MdocEncodingException.class, () -> MdocParser.parse(new byte[0]));
        assertEquals("Input bytes are null or empty", ex.getMessage());
    }

    @Test
    void shouldThrowOnSchemaValidationError() {
        // This mDoc is malformed because `documents` should be an array not a map
        CBORPairList malformed = new CBORPairList(
                new CBORPair(new CBORString("version"), new CBORInteger(1)),
                new CBORPair(new CBORString("documents"), new CBORPairList(List.of())),
                new CBORPair(new CBORString("status"), new CBORInteger(0)));

        var ex = assertThrows(MdocEncodingException.class, () -> MdocParser.parse(malformed.encode()));
        assertTrue(ex.getMessage().startsWith("mDoc fails schema validation:"));
        assertTrue(ex.getMessage()
                .contains("\"instanceLocation\":\"/documents\",\"message\":\"object found, array expected\""));
    }
}
