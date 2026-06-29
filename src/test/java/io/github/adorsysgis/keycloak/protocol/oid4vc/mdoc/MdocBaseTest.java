package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEKeyBuilder;
import com.authlete.cose.COSEProtectedHeader;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import com.authlete.cose.constants.COSEAlgorithms;
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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.bouncycastle.util.encoders.Hex;
import org.keycloak.util.JsonSerialization;

public class MdocBaseTest {

    protected static String readResource(String resourcePath) {
        try {
            var resource = MdocParserTest.class.getResource(resourcePath);
            assertNotNull(resource);
            return Files.readString(Path.of(resource.toURI())).trim();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected DeviceResponse buildDeviceResponse() throws Exception {
        return buildDeviceResponse(getDefaultMdocVerificationOpts().build());
    }

    protected DeviceResponse buildDeviceResponse(MdocVerificationOpts opts) throws Exception {
        String docType = "com.example.doctype";
        Map<String, Object> claims = JsonSerialization.readValue("""
                {
                  "com.example.namespace1": {
                    "claimName1": "claimValue1"
                  }
                }""", new TypeReference<>() {});

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        ValidityInfo validityInfo = new ValidityInfo(now, now, now.plusYears(10));

        COSEEC2Key issuerKey = getIssuerKeyRef1();
        X509Certificate issuerCert = getIssuerCertRef1();
        List<X509Certificate> issuerCertChain = List.of(issuerCert);

        COSEEC2Key deviceKey = getDeviceKeyRef1();

        IssuerSigned issuerSigned = new IssuerSignedBuilder()
                .setDocType(docType)
                .setClaims(claims)
                .setValidityInfo(validityInfo)
                .setIssuerKey(issuerKey)
                .setIssuerCertChain(issuerCertChain)
                .setDeviceKey(deviceKey)
                .build();

        DeviceNameSpaces deviceNamespaces = new DeviceNameSpaces(List.of());
        CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_OID4VPSpec(opts);
        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString(MdocConstants.L_DEVICE_AUTHENTICATION),
                sessionTranscript,
                new CBORString(docType),
                CborUtil.wrap(deviceNamespaces.encode()));

        var deviceSignature = sign1(CborUtil.wrap(deviceAuthentication.encode()), deviceKey);
        DeviceSigned deviceSigned =
                new DeviceSigned(new DeviceNameSpacesBytes(deviceNamespaces), new DeviceAuth(deviceSignature));

        Document document = new Document(docType, issuerSigned, deviceSigned, null);
        return new DeviceResponse(List.of(document));
    }

    private static COSESign1 sign1(CBORTaggedItem payload, COSEEC2Key key) throws COSEException {
        COSEProtectedHeader protectedHeader =
                new COSEProtectedHeaderBuilder().alg(COSEAlgorithms.ES256).build();

        SigStructure structure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload.encode())
                .build();

        byte[] signature = new COSESigner(key.toECPrivateKey()).sign(structure, COSEAlgorithms.ES256);
        return new COSESign1Builder()
                .protectedHeader(new COSEProtectedHeaderBuilder()
                        .alg(COSEAlgorithms.ES256)
                        .build())
                .signature(signature)
                .build();
    }

    protected static MdocVerificationOpts.Builder getDefaultMdocVerificationOpts() {
        return MdocVerificationOpts.builder()
                .withClientId("x509_san_dns:example.com")
                .withOid4vpNonce("exc7gBkxjx1rdc9udRrveKvSsJIq80avlXeLHhGwqtA")
                .withResponseUri("https://example.com/response")
                .withJwkThumbprint(Hex.decode("4283ec927ae0f208daaa2d026a814f2b22dca52cf85ffa8f3f8626c6bd669047"));
    }

    protected static COSEEC2Key getIssuerKeyRef1() {
        return new COSEKeyBuilder()
                .ktyEC2()
                .ec2CrvP256()
                .ec2XInBase64Url("qicwMwft93DFCdJxwPFBLtghVyusT5qHlnSyWaRlnC0")
                .ec2YInBase64Url("hLB3NgHh0bDJZf_gdLglkZH566VIByBGB5eXje8rxmg")
                .ec2DInBase64Url("NcGG9RM19Wyb4XF_RNP9ONB-MftuL3ELFdy_Q0LCX6g")
                .buildEC2Key();
    }

    protected static X509Certificate getIssuerCertRef1() {
        return toCert(str("""
            MIIBlzCCAT2gAwIBAgIUNPf1jk/kxePsVn/ntNMpN3IHqGMwCgYIKoZIzj0EAwIw
            IDEeMBwGA1UEAwwVQ09TRSBJc3N1ZXIgMTAwIFllYXJzMCAXDTI2MDYyOTEwMjcz
            MFoYDzIxMjYwNjA1MTAyNzMwWjAgMR4wHAYDVQQDDBVDT1NFIElzc3VlciAxMDAg
            WWVhcnMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASqJzAzB+33cMUJ0nHA8UEu
            2CFXK6xPmoeWdLJZpGWcLYSwdzYB4dGwyWX/4HS4JZGR+eulSAcgRgeXl43vK8Zo
            o1MwUTAdBgNVHQ4EFgQUl8hm4O6VpuB0A5yhQe/zJxAJr54wHwYDVR0jBBgwFoAU
            l8hm4O6VpuB0A5yhQe/zJxAJr54wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQD
            AgNIADBFAiA0LGtfjdKY+1wxDzozcOTP+xB5Zcqf0GhCONvabiMRiAIhANR38jES
            b7jxK0rLtDSKKWvzHBx3ChgwKq7o+N+fqp4t
        """));
    }

    protected static COSEEC2Key getDeviceKeyRef1() {
        return new COSEKeyBuilder()
                .ktyEC2()
                .ec2CrvP256()
                .ec2XInBase64Url("ohTRw0pu0YZafMvv8xfip6uBgTG0ecd1NJTlu92BsYY")
                .ec2YInBase64Url("nZDEU7-G2Ij3gNA2I5Y8ngAf7r-vGeBeI9p9bj8glFc")
                .ec2DInBase64Url("6hgQOsgeFUXDmEA8wsxslFSqYF5EoJ858ebE29HdV5w")
                .buildEC2Key();
    }

    public static X509Certificate toCert(String cert) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] bytes = Base64.getDecoder().decode(cert);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static String str(String input) {
        return input.replaceAll("\\s+", "");
    }
}
