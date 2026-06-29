package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEEC2Key;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEKeyBuilder;
import com.authlete.cose.COSEMac0;
import com.authlete.cose.COSEProtectedHeader;
import com.authlete.cose.COSEProtectedHeaderBuilder;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSESign1Builder;
import com.authlete.cose.COSESigner;
import com.authlete.cose.COSEUnprotectedHeader;
import com.authlete.cose.COSEUnprotectedHeaderBuilder;
import com.authlete.cose.SigStructure;
import com.authlete.cose.SigStructureBuilder;
import com.authlete.cose.constants.COSEAlgorithms;
import com.authlete.mdoc.AuthorizedNameSpaces;
import com.authlete.mdoc.DeviceAuth;
import com.authlete.mdoc.DeviceKeyInfo;
import com.authlete.mdoc.DeviceNameSpaces;
import com.authlete.mdoc.DeviceNameSpacesBytes;
import com.authlete.mdoc.DeviceResponse;
import com.authlete.mdoc.DeviceSigned;
import com.authlete.mdoc.DigestIDs;
import com.authlete.mdoc.DigestIDsEntry;
import com.authlete.mdoc.Document;
import com.authlete.mdoc.IssuerNameSpaces;
import com.authlete.mdoc.IssuerSigned;
import com.authlete.mdoc.IssuerSignedBuilder;
import com.authlete.mdoc.KeyAuthorizations;
import com.authlete.mdoc.MobileSecurityObject;
import com.authlete.mdoc.MobileSecurityObjectBytes;
import com.authlete.mdoc.ValidityInfo;
import com.authlete.mdoc.ValueDigests;
import com.authlete.mdoc.ValueDigestsEntry;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.util.encoders.Hex;
import org.keycloak.crypto.JavaAlgorithm;

public class MdocBaseTest {

    public static final int DEFAULT_RESPONSE_VALIDITY_MINS = 10;
    public static final String DOC_TYPE = "com.example.doctype";
    public static final String NAMESPACE = "com.example.namespace1";

    /**
     * Mutable build-context handed to an {@link IssuerSignedCustomizer}. Defaults reflect the
     * standard issuer key / certificate, the SHA-256 digest of the standard claims, and a MSO
     * with SHA-256 as the digest algorithm. Tests may override any of these and then call
     * {@link #signMsoAndWrap()} to produce the final {@link IssuerSigned}.
     */
    protected static final class IssueContext {
        public final IssuerNameSpaces nameSpaces;
        public MobileSecurityObject mso;
        public COSEEC2Key signingKey;
        public List<X509Certificate> certChain;

        IssueContext(
                IssuerNameSpaces ns, MobileSecurityObject mso, COSEEC2Key signingKey, List<X509Certificate> certChain) {
            this.nameSpaces = ns;
            this.mso = mso;
            this.signingKey = signingKey;
            this.certChain = certChain;
        }

        public IssuerSigned signMsoAndWrap() throws Exception {
            return new IssuerSigned(nameSpaces, signIssuerAuth(mso, signingKey, certChain));
        }
    }

    @FunctionalInterface
    protected interface IssuerSignedCustomizer {
        IssuerSigned customize(IssueContext ctx) throws Exception;
    }

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
        return buildDeviceResponse(getDefaultMdocVerificationOpts().build(), null);
    }

    protected DeviceResponse buildDeviceResponse(MdocVerificationOpts opts) throws Exception {
        return buildDeviceResponse(opts, null);
    }

    protected DeviceResponse buildDeviceResponse(MdocVerificationOpts opts, IssuerSignedCustomizer customizer)
            throws Exception {
        BuiltStandard built = buildStandardComponents();
        DeviceSigned deviceSigned = buildDeviceSigned(opts);

        IssueContext ctx =
                new IssueContext(built.nameSpaces, built.mso, getIssuerKeyRef1(), List.of(getIssuerCertRef1()));
        IssuerSigned issuerSigned = (customizer == null) ? ctx.signMsoAndWrap() : customizer.customize(ctx);

        return new DeviceResponse(List.of(new Document(DOC_TYPE, issuerSigned, deviceSigned, null)));
    }

    private record BuiltStandard(IssuerNameSpaces nameSpaces, MobileSecurityObject mso) {}

    private static BuiltStandard buildStandardComponents() throws Exception {
        Map<String, Object> claims = Map.of(NAMESPACE, Map.of("claimName1", "claimValue1"));

        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC).withNano(0);
        ValidityInfo validityInfo = new ValidityInfo(now, now, now.plusMinutes(DEFAULT_RESPONSE_VALIDITY_MINS));

        IssuerSigned baseline = new IssuerSignedBuilder()
                .setDocType(DOC_TYPE)
                .setClaims(claims)
                .setValidityInfo(validityInfo)
                .setIssuerKey(getIssuerKeyRef1())
                .setIssuerCertChain(List.of(getIssuerCertRef1()))
                .setDeviceKey(getDeviceKeyRef1())
                .build();

        IssuerNameSpaces nameSpaces = (IssuerNameSpaces)
                baseline.findByKey(MdocConstants.L_NAME_SPACES).getValue();

        // Re-build an equivalent SHA-256 MSO from scratch; tests that need a different
        // digest algorithm or valueDigests simply swap ctx.mso before calling signMsoAndWrap.
        MobileSecurityObject mso = buildStandardMSO(nameSpaces, validityInfo);
        return new BuiltStandard(nameSpaces, mso);
    }

    /**
     * Builds a stock MSO equivalent to the one produced by {@link IssuerSignedBuilder} using
     * SHA-256 over the standard claims. Tests can replace {@link IssueContext#mso} with a
     * different MSO when they need a non-default algorithm or valueDigests.
     */
    private static MobileSecurityObject buildStandardMSO(IssuerNameSpaces nameSpaces, ValidityInfo validityInfo)
            throws Exception {
        ValueDigests standardDigests = buildValueDigests(nameSpaces);
        DeviceKeyInfo dki = new DeviceKeyInfo(
                getDeviceKeyRef1(),
                new KeyAuthorizations(new AuthorizedNameSpaces(List.of(new CBORString(NAMESPACE))), null),
                null);
        return new MobileSecurityObject("1.0", JavaAlgorithm.SHA256, standardDigests, dki, DOC_TYPE, validityInfo);
    }

    private static ValueDigests buildValueDigests(IssuerNameSpaces nameSpaces) {
        // Compute SHA-256 over each IssuerSignedItemBytes under each namespace.
        List<ValueDigestsEntry> entries = new ArrayList<>();
        for (var nsPair : nameSpaces.getPairs()) {
            String namespace = ((CBORString) nsPair.getKey()).getValue();
            CBORItemList items = (CBORItemList) nsPair.getValue();
            List<DigestIDsEntry> digests = new ArrayList<>();
            int digestId = 1;
            for (var item : items.getItems()) {
                byte[] hash = DigestUtils.sha256(item.encode());
                digests.add(new DigestIDsEntry(new CBORInteger(digestId++), new CBORByteArray(hash)));
            }
            entries.add(new ValueDigestsEntry(new CBORString(namespace), new DigestIDs(digests)));
        }
        return new ValueDigests(entries);
    }

    private static DeviceSigned buildDeviceSigned(MdocVerificationOpts opts) throws COSEException {
        DeviceNameSpacesBytes deviceNameSpaces = new DeviceNameSpacesBytes(new DeviceNameSpaces(List.of()));
        CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_OID4VPSpec(opts);
        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString(MdocConstants.L_DEVICE_AUTHENTICATION),
                sessionTranscript,
                new CBORString(DOC_TYPE),
                deviceNameSpaces);

        var deviceSignature = signDeviceSignature(CborUtil.wrap(deviceAuthentication.encode()), getDeviceKeyRef1());
        return new DeviceSigned(deviceNameSpaces, new DeviceAuth(deviceSignature));
    }

    /**
     * Wraps an MSO into a COSE_Sign1 signed by the given key and carrying the given x5chain.
     * Pass an empty list to attach no issuer certificate.
     */
    protected static COSESign1 signIssuerAuth(
            MobileSecurityObject mso, COSEEC2Key issuerKey, List<X509Certificate> x5chain) throws Exception {
        COSEProtectedHeader protectedHeader =
                new COSEProtectedHeaderBuilder().alg(COSEAlgorithms.ES256).build();
        COSEUnprotectedHeader unprotectedHeader = (x5chain == null || x5chain.isEmpty())
                ? null
                : new COSEUnprotectedHeaderBuilder().x5chain(x5chain).build();

        MobileSecurityObjectBytes msoBytes = new MobileSecurityObjectBytes(mso);
        CBORByteArray payload = new CBORByteArray(msoBytes.encode(), msoBytes);
        SigStructure sigStructure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload)
                .build();
        byte[] signature = new COSESigner(issuerKey.toECPrivateKey()).sign(sigStructure, COSEAlgorithms.ES256);

        var builder = new COSESign1Builder()
                .protectedHeader(protectedHeader)
                .payload(payload)
                .signature(signature);
        if (unprotectedHeader != null) {
            builder.unprotectedHeader(unprotectedHeader);
        }
        return builder.build();
    }

    private static COSESign1 signDeviceSignature(CBORTaggedItem payload, COSEEC2Key deviceKey) throws COSEException {
        COSEProtectedHeader protectedHeader =
                new COSEProtectedHeaderBuilder().alg(COSEAlgorithms.ES256).build();

        SigStructure structure = new SigStructureBuilder()
                .signature1()
                .bodyAttributes(protectedHeader)
                .payload(payload.encode())
                .build();

        byte[] signature = new COSESigner(deviceKey.toECPrivateKey()).sign(structure, COSEAlgorithms.ES256);
        return new COSESign1Builder()
                .protectedHeader(new COSEProtectedHeaderBuilder()
                        .alg(COSEAlgorithms.ES256)
                        .build())
                .signature(signature)
                .build();
    }

    /**
     * Returns a copy of the given {@link ValueDigests} with the listed namespaces removed.
     */
    protected static ValueDigests withValueDigestsExcluding(ValueDigests original, String... excludedNamespaces) {
        List<ValueDigestsEntry> entries = new ArrayList<>();
        for (var pair : original.getPairs()) {
            ValueDigestsEntry entry = (ValueDigestsEntry) pair;
            String namespace = ((CBORString) entry.getKey()).getValue();
            if (!List.of(excludedNamespaces).contains(namespace)) {
                entries.add(entry);
            }
        }
        return new ValueDigests(entries);
    }

    /**
     * Returns a copy of {@code original} where the first digest entry under {@code namespace}
     *  has each byte XORed with 0xFF - simulates a corrupted digest.
     */
    protected static ValueDigests withTamperedDigest(ValueDigests original, String namespace) {
        List<ValueDigestsEntry> entries = new ArrayList<>();
        for (var pair : original.getPairs()) {
            ValueDigestsEntry entry = (ValueDigestsEntry) pair;
            String ns = ((CBORString) entry.getKey()).getValue();
            DigestIDs digestIDs = (DigestIDs) entry.getValue();
            if (ns.equals(namespace)) {
                List<DigestIDsEntry> tamperedList = new ArrayList<>();
                for (var dp : digestIDs.getPairs()) {
                    DigestIDsEntry d = (DigestIDsEntry) dp;
                    byte[] orig = ((CBORByteArray) d.getValue()).getValue();
                    byte[] flipped = new byte[orig.length];
                    for (int i = 0; i < flipped.length; i++) {
                        flipped[i] = (byte) (orig[i] ^ 0xFF);
                    }
                    tamperedList.add(new DigestIDsEntry((CBORInteger) d.getKey(), new CBORByteArray(flipped)));
                }
                entries.add(new ValueDigestsEntry((CBORString) entry.getKey(), new DigestIDs(tamperedList)));
            } else {
                entries.add(entry);
            }
        }
        return new ValueDigests(entries);
    }

    protected static Document extractDocument(DeviceResponse dr) {
        CBORItemList documents =
                (CBORItemList) dr.findByKey(MdocConstants.L_DOCUMENTS).getValue();
        return (Document) documents.getItems().getFirst();
    }

    protected static ValueDigests extractValueDigests(MobileSecurityObject mso) {
        return (ValueDigests) mso.findByKey(MdocConstants.L_VALUE_DIGESTS).getValue();
    }

    /**
     * Returns a fresh MSO whose {@code valueDigests} and {@code digestAlgorithm} come from the
     * supplied arguments; all remaining fields are carried over from {@code baseline}.
     */
    protected static MobileSecurityObject rebuildMso(
            MobileSecurityObject baseline, ValueDigests digests, String algorithm) {
        String docType =
                ((CBORString) baseline.findByKey(MdocConstants.L_DOC_TYPE).getValue()).getValue();
        DeviceKeyInfo dki = (DeviceKeyInfo)
                baseline.findByKey(MdocConstants.L_DEVICE_KEY_INFO).getValue();
        ValidityInfo vi =
                (ValidityInfo) baseline.findByKey(MdocConstants.L_VALIDITY_INFO).getValue();
        return new MobileSecurityObject("1.0", algorithm, digests, dki, docType, vi);
    }

    /**
     * Returns a copy of {@code baseline} whose deviceAuth carries a {@code deviceMac} (a dummy
     * COSE_Mac0) in place of the device signature. Triggers the missing-device-signature path
     * in {@code MdocVerificationContext}.
     */
    protected static DeviceResponse withDeviceMac(DeviceResponse baseline) {
        Document doc = extractDocument(baseline);
        DeviceSigned baselineSigned =
                (DeviceSigned) doc.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue();
        DeviceNameSpacesBytes deviceNameSpaces = (DeviceNameSpacesBytes)
                baselineSigned.findByKey(MdocConstants.L_NAME_SPACES).getValue();
        IssuerSigned issuerSigned =
                (IssuerSigned) doc.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();

        COSEMac0 mac0 = new COSEMac0(
                new COSEProtectedHeaderBuilder().alg(COSEAlgorithms.ES256).build(),
                new COSEUnprotectedHeader(Collections.emptyList()),
                CBORNull.INSTANCE,
                new CBORByteArray(new byte[32]));

        return new DeviceResponse(List.of(
                new Document(DOC_TYPE, issuerSigned, new DeviceSigned(deviceNameSpaces, new DeviceAuth(mac0)), null)));
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

    /**
     * X.509 certificate from the ISO 18013-5 spec sample
     */
    protected static String getSpecSampleCert() {
        return str("""
            MIICXDCCAgGgAwIBAgIKR1IJyTwoAKFf/zAKBggqhkjOPQQDAjBFMQswCQYDVQQG
            EwJVUzEpMCcGA1UEAwwgSVNPMTgwMTMtNSBUZXN0IENlcnRpZmljYXRlIElBQ0Ex
            CzAJBgNVBAgMAk5ZMB4XDTI0MDQyODIxMDIyM1oXDTI1MDcyOTIxMDIyM1owRDEL
            MAkGA1UEBhMCVVMxKDAmBgNVBAMMH0lTTzE4MDEzLTUgVGVzdCBDZXJ0aWZpY2F0
            ZSBEU0MxCzAJBgNVBAgMAk5ZMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN04V
            oqv1bGCkVaXMXxWZ9yEG9PALWgfUxo/rzmwcoaat5A9WyptKUcAEZNY+tyduGU9t
            AusOxkfTeCCd1+PDvKOB2TCB1jAdBgNVHQ4EFgQUZSkNyyy+We9Wu99FbU/4pFp9
            7lowHwYDVR0jBBgwFoAUTP+VJeBlm1DsHEMKWnKNxBtNOs8wDgYDVR0PAQH/BAQD
            AgeAMB0GA1UdEQQWMBSBEmV4YW1wbGVAaXNvbWRsLmNvbTAdBgNVHRIEFjAUgRJl
            eGFtcGxlQGlzb21kbC5jb20wLwYDVR0fBCgwJjAkoCKgIIYeaHR0cHM6Ly9leGFt
            cGxlLmNvbS9JU09tREwuY3JsMBUGA1UdJQEB/wQLMAkGByiBjF0FAQIwCgYIKoZI
            zj0EAwIDSQAwRgIhAK/DzBi2gOVCUHOoxgXpTQpcrV8ULl/Q0ROYqS3Gr6NZAiEA
            o4i3TOyNcI7ZMm+0JrzUdAM6gM4K9zhOnmPOnitbtUM=
            """);
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
