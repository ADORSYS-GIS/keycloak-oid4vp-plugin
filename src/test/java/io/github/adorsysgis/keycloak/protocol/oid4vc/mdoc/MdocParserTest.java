package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.authlete.cbor.CBORDecoder;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEKeyBuilder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.mdoc.DeviceAuth;
import com.authlete.mdoc.DeviceNameSpaces;
import com.authlete.mdoc.DeviceNameSpacesBytes;
import com.authlete.mdoc.DeviceResponse;
import com.authlete.mdoc.DeviceSigned;
import com.authlete.mdoc.Document;
import com.authlete.mdoc.IssuerSigned;
import com.authlete.mdoc.IssuerSignedBuilder;
import com.authlete.mdoc.ValidityInfo;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.keycloak.util.JsonSerialization;

public class MdocParserTest {

    @Test
    void shouldParseBase64UrlEncodedDeviceResponse() throws Exception {
        DeviceResponse deviceResponse = buildDeviceResponse();
        String encoded = deviceResponse.encodeToBase64Url();

        CBORPairList parsed = MdocParser.parseBase64Url(encoded);
        assertNotNull(parsed);
        assertEquals(encoded, parsed.encodeToBase64Url());
    }

    @Test
    void shouldParseRawBytesDeviceResponse() throws Exception {
        DeviceResponse deviceResponse = buildDeviceResponse();
        byte[] encoded = deviceResponse.encode();

        CBORPairList parsed = MdocParser.parse(encoded);
        assertNotNull(parsed);
        assertTrue(parsed.encode().length > 0);
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

    private static String readResource(String resourcePath) {
        try {
            var resource = MdocParserTest.class.getResource(resourcePath);
            assertNotNull(resource);
            return Files.readString(Path.of(resource.toURI())).trim();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private DeviceResponse buildDeviceResponse() throws CertificateException, COSEException, IOException {
        String docType = "com.example.doctype";

        Map<String, Object> claims = JsonSerialization.readValue("""
                {
                  "com.example.namespace1": {
                    "claimName1": "claimValue1"
                  }
                }""", new TypeReference<>() {});

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        ValidityInfo validityInfo = new ValidityInfo(now, now, now.plusYears(10));

        COSEEC2Key issuerKey = new COSEKeyBuilder()
                .ktyEC2()
                .ec2CrvP256()
                .ec2XInBase64Url("Qw7367PjIwU17ckX_G4ZqLW2EjPG0efV0cYzhvq2Ujk")
                .ec2YInBase64Url("Mpq3N90VZIBBOqvYgAHi4ZfOSK2gM09_UozgVdRCrt4")
                .ec2DInBase64Url("IzdjF8wyUSqsCbz8kh6ysJOUcK003aCt9hIGFiGWlzI")
                .buildEC2Key();

        String issuerCertPem = """
                -----BEGIN CERTIFICATE-----
                MIIBXzCCAQSgAwIBAgIGAYwpA4/aMAoGCCqGSM49BAMCMDYxNDAyBgNVBAMMKzNf
                d1F3Y3Qxd28xQzBST3FfWXRqSTRHdTBqVXRiVTJCQXZteEltQzVqS3MwHhcNMjMx
                MjAyMDUzMjI4WhcNMjQwOTI3MDUzMjI4WjA2MTQwMgYDVQQDDCszX3dRd2N0MXdv
                MUMwUk9xX1l0akk0R3UwalV0YlUyQkF2bXhJbUM1aktzMFkwEwYHKoZIzj0CAQYI
                KoZIzj0DAQcDQgAEQw7367PjIwU17ckX/G4ZqLW2EjPG0efV0cYzhvq2Ujkymrc3
                3RVkgEE6q9iAAeLhl85IraAzT39SjOBV1EKu3jAKBggqhkjOPQQDAgNJADBGAiEA
                o4TsuxDl5+3eEp6SHDrBVn1rqOkGGLoOukJhelndGqICIQCpocrjWDwrWexoQZOO
                rwnEYRBmmfhaPor2OZCrbP3U6w==
                -----END CERTIFICATE-----
                """;

        X509Certificate issuerCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(issuerCertPem.getBytes(StandardCharsets.UTF_8)));

        List<X509Certificate> issuerCertChain = List.of(issuerCert);

        COSEEC2Key deviceKey = new COSEKeyBuilder()
                .ktyEC2()
                .ec2CrvP256()
                .ec2XInBase64Url("g-gO_BofI8VbT7_xJm-W7500Aenm_yVvBqZ0EshFWhY")
                .ec2YInBase64Url("T2U2U3M4ZjVhNlI3YzhKOWwwbTFhMmIzYzRkNWU2Zjc")
                .ec2DInBase64Url("ZDFzM2Y0ZzVoNmo3azhsOW0wYTFhMmIzYzRkNWU2Zjc")
                .buildEC2Key();

        IssuerSigned issuerSigned = new IssuerSignedBuilder()
                .setDocType(docType)
                .setClaims(claims)
                .setValidityInfo(validityInfo)
                .setIssuerKey(issuerKey)
                .setIssuerCertChain(issuerCertChain)
                .setDeviceKey(deviceKey)
                .build();

        COSESign1 mockDeviceSignature =
                new COSESign1Builder().signature(new byte[] {}).build();
        DeviceSigned deviceSigned = new DeviceSigned(
                new DeviceNameSpacesBytes(new DeviceNameSpaces(List.of())), new DeviceAuth(mockDeviceSignature));

        Document document = new Document(docType, issuerSigned, deviceSigned, null);
        return new DeviceResponse(List.of(document));
    }
}
