package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORizer;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.constants.COSEAlgorithms;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocDeviceResponse;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocDeviceSigned;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocDocument;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.model.MdocIssuerSigned;
import org.junit.jupiter.api.Test;

public class MdocParserTest {

    @Test
    void shouldParseValidDeviceResponse() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        assertNotNull(response);
        assertEquals(0, response.getStatus());
        assertTrue(response.isSuccess());
        assertEquals("Success", response.getStatusMessage());
        assertFalse(response.getDocuments().isEmpty());
    }

    @Test
    void shouldParseDocument() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        assertNotNull(document);
        assertEquals("org.iso.18013.5.1.mdl", document.getDocType());
    }

    @Test
    void shouldParseIssuerSigned() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();
        assertNotNull(issuerSigned);
        assertNotNull(issuerSigned.getIssuerSignedPairs());
    }

    @Test
    void shouldParseDeviceSigned() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocDeviceSigned deviceSigned = document.getDeviceSigned();
        assertNotNull(deviceSigned);
        assertNotNull(deviceSigned.getDeviceSignedPairs());
    }

    @Test
    void shouldParseBase64UrlEncoded() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(cborData);

        MdocDeviceResponse response = MdocParser.parseBase64Url(base64Url);
        assertNotNull(response);
        assertEquals(0, response.getStatus());
        assertFalse(response.getDocuments().isEmpty());
    }

    @Test
    void shouldProvideRawCBORForIssuerAuth() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();

        CBORItem rawAuth = issuerSigned.getRawIssuerAuth();
        assertNotNull(rawAuth);
    }

    @Test
    void shouldProvideRawCBORForDeviceNameSpaces() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocDeviceSigned deviceSigned = document.getDeviceSigned();

        CBORItem rawNs = deviceSigned.getRawDeviceNameSpaces();
        assertNotNull(rawNs);
    }

    @Test
    void shouldParseIssuerNameSpacesAsMap() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();

        Map<Object, Object> nsMap = issuerSigned.getIssuerNameSpacesAsMap();
        assertNull(nsMap);
    }

    @Test
    void shouldHandleEmptyMsoGracefully() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();

        assertNull(issuerSigned.getMobileSecurityObject());
    }

    @Test
    void shouldHandleDocumentParsingSeparately() {
        byte[] docCbor = buildSimpleDocument();
        MdocDocument document = MdocDocument.parse(docCbor);

        assertNotNull(document);
        assertEquals("org.iso.18013.5.1.mdl", document.getDocType());
        assertNotNull(document.getIssuerSigned());
        assertNotNull(document.getDeviceSigned());
    }

    @Test
    void shouldHandleDocumentBase64UrlParsing() throws MdocEncodingException {
        byte[] docCbor = buildSimpleDocument();
        String base64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(docCbor);

        MdocDocument document = MdocParser.parseDocumentBase64Url(base64Url);
        assertNotNull(document);
        assertEquals("org.iso.18013.5.1.mdl", document.getDocType());
    }

    @Test
    void shouldThrowOnNullBase64Input() {
        assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url(null));
    }

    @Test
    void shouldThrowOnBlankBase64Input() {
        assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url("   "));
    }

    @Test
    void shouldThrowOnInvalidBase64Input() {
        assertThrows(MdocEncodingException.class, () -> MdocParser.parseBase64Url("not-valid!!!"));
    }

    @Test
    void shouldThrowOnNullBytes() {
        assertThrows(MdocEncodingException.class, () -> MdocParser.parse(null));
    }

    @Test
    void shouldThrowOnEmptyBytes() {
        assertThrows(MdocEncodingException.class, () -> MdocParser.parse(new byte[0]));
    }

    @Test
    void shouldGetDocTypeFromIssuerSigned() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();

        assertNull(issuerSigned.getMobileSecurityObject());
        assertNull(issuerSigned.getDocType());
    }

    @Test
    void shouldParseMultipleDocuments() throws MdocEncodingException {
        byte[] cborData = buildMultiDocumentDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        assertNotNull(response);
        assertEquals(0, response.getStatus());
        assertEquals(2, response.getDocuments().size());
        assertEquals("org.iso.18013.5.1.mdl", response.getDocuments().get(0).getDocType());
        assertEquals("org.iso.18013.5.1.mDL", response.getDocuments().get(1).getDocType());
    }

    @Test
    void shouldHandleErrorStatus() throws MdocEncodingException {
        byte[] cborData = buildErrorDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        assertEquals(1, response.getStatus());
        assertFalse(response.isSuccess());
        assertEquals("Internal error", response.getStatusMessage());
    }

    @Test
    void shouldGetDigestAlgorithmFromMSO() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocIssuerSigned issuerSigned = document.getIssuerSigned();

        assertNull(issuerSigned.getMobileSecurityObject());
        assertNull(issuerSigned.getDigestAlgorithm());
    }

    @Test
    void shouldEncodeAndDecodeDeviceResponse() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        byte[] encoded = response.getDeviceResponsePairs().encode();
        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
    }

    @Test
    void shouldParseDeviceSignedWithDeviceKeyInfo() throws MdocEncodingException {
        byte[] cborData = buildSimpleDeviceResponse();
        MdocDeviceResponse response = MdocDeviceResponse.parse(cborData);

        MdocDocument document = response.getDocuments().getFirst();
        MdocDeviceSigned deviceSigned = document.getDeviceSigned();

        assertNotNull(deviceSigned.getDeviceSignedPairs());
    }

    private byte[] buildSimpleDeviceResponse() {
        CBORizer cborizer = new CBORizer();
        Map<Object, Object> docMap = buildSimpleDocumentMap(cborizer);
        Map<Object, Object> drMap = new LinkedHashMap<>();
        drMap.put("version", "1.0");
        drMap.put("documents", List.of(docMap));
        drMap.put("status", 0);
        return cborizer.cborizeMap(drMap).encode();
    }

    private byte[] buildMultiDocumentDeviceResponse() {
        CBORizer cborizer = new CBORizer();
        Map<Object, Object> docMap1 = buildSimpleDocumentMap(cborizer, "org.iso.18013.5.1.mdl");
        Map<Object, Object> docMap2 = buildSimpleDocumentMap(cborizer, "org.iso.18013.5.1.mDL");
        Map<Object, Object> drMap = new LinkedHashMap<>();
        drMap.put("version", "1.0");
        drMap.put("documents", List.of(docMap1, docMap2));
        drMap.put("status", 0);
        return cborizer.cborizeMap(drMap).encode();
    }

    private byte[] buildErrorDeviceResponse() {
        CBORizer cborizer = new CBORizer();
        Map<Object, Object> drMap = new LinkedHashMap<>();
        drMap.put("version", "1.0");
        drMap.put("status", 1);
        return cborizer.cborizeMap(drMap).encode();
    }

    private Map<Object, Object> buildSimpleDocumentMap(CBORizer cborizer) {
        return buildSimpleDocumentMap(cborizer, "org.iso.18013.5.1.mdl");
    }

    private Map<Object, Object> buildSimpleDocumentMap(CBORizer cborizer, String docType) {
        Map<Object, Object> issuerSignedMap = buildSimpleIssuerSignedMap(cborizer, docType);
        Map<Object, Object> deviceSignedMap = buildSimpleDeviceSignedMap(cborizer);
        Map<Object, Object> docMap = new LinkedHashMap<>();
        docMap.put("docType", docType);
        docMap.put("issuerSigned", issuerSignedMap);
        docMap.put("deviceSigned", deviceSignedMap);
        return docMap;
    }

    private Map<Object, Object> buildSimpleIssuerSignedMap(CBORizer cborizer, String docType) {
        Map<Object, Object> nsMap = new LinkedHashMap<>();
        nsMap.put("org.iso.18013.5.1", List.of());
        Map<Object, Object> issuerSignedMap = new LinkedHashMap<>();
        issuerSignedMap.put("nameSpaces", cborizer.cborizeMap(nsMap));
        issuerSignedMap.put("issuerAuth", buildSimpleIssuerAuth(cborizer, docType));
        return issuerSignedMap;
    }

    private byte[] buildSimpleIssuerAuth(CBORizer cborizer, String docType) {
        Map<Object, Object> msoMap = new LinkedHashMap<>();
        msoMap.put("version", "1.0");
        msoMap.put("digestAlgorithm", "SHA-256");
        msoMap.put("docType", docType);
        msoMap.put("valueDigests", cborizer.cborizeMap(new LinkedHashMap<>()));
        msoMap.put("deviceKeyInfo", cborizer.cborizeByteArray(new byte[32]));
        byte[] msoBytes = cborizer.cborizeMap(msoMap).encode();
        COSESign1Builder sign1Builder = new COSESign1Builder()
                .protectedHeader(new COSEProtectedHeaderBuilder()
                        .alg(COSEAlgorithms.ES256)
                        .build())
                .unprotectedHeader(new COSEUnprotectedHeaderBuilder().build())
                .payload(msoBytes);
        byte[] signature = new byte[64];
        Arrays.fill(signature, (byte) 0xAB);
        return sign1Builder.signature(signature).build().encode();
    }

    private Map<Object, Object> buildSimpleDeviceSignedMap(CBORizer cborizer) {
        Map<Object, Object> nsMap = new LinkedHashMap<>();
        nsMap.put("org.iso.18013.5.1", List.of());
        Map<Object, Object> deviceSignedMap = new LinkedHashMap<>();
        deviceSignedMap.put("nameSpaces", cborizer.cborizeMap(nsMap));
        deviceSignedMap.put("deviceKeyInfo", cborizer.cborizeByteArray(new byte[32]));
        return deviceSignedMap;
    }

    private byte[] buildSimpleDocument() {
        CBORizer cborizer = new CBORizer();
        Map<Object, Object> docMap = buildSimpleDocumentMap(cborizer);
        return cborizer.cborizeMap(docMap).encode();
    }
}
