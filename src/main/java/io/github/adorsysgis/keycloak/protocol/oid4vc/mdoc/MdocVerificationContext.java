package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORParser;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSEKey;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.crypto.PKIXVerificationUtil;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.util.JsonSerialization;

/**
 * Runs verification of mDoc device responses.
 *
 * @see <a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5:2021</a>
 */
public class MdocVerificationContext {

    private static final Logger logger = Logger.getLogger(MdocVerificationContext.class);

    // The issuing authority infrastructure shall use one of the following digest algorithms:
    // SHA-256, SHA-384 or SHA-512 as specified in ISO/IEC 10118-3.
    private static final List<String> allowedDigestAlgs =
            List.of(JavaAlgorithm.SHA256, JavaAlgorithm.SHA384, JavaAlgorithm.SHA512);

    private final CBORPairList mdoc;

    public MdocVerificationContext(String mdoc) throws VerificationException {
        try {
            this.mdoc = MdocParser.parseBase64Url(mdoc);
        } catch (MdocEncodingException e) {
            throw new VerificationException("Failed to parse subject as an mDoc device response", e);
        }
    }

    /**
     * Verifies mDoc presentation.
     *
     * @param opts                            Options to parameterize the mDoc verification.
     * @param presentationRequirements        If set, the presentation requirements will be enforced on the claims
     *                                        in the mDoc upon verification.
     * @param truststoreProvider              Truststore for enforcing PKIX trust in the issuer's X.5C chain.
     * @throws VerificationException if verification failed
     */
    public void verifyPresentation(
            MdocVerificationOpts opts,
            PresentationRequirements presentationRequirements,
            TruststoreProvider truststoreProvider)
            throws VerificationException {
        // Verify response status BAE
        verifyResponseStatus(mdoc);

        // Verify issuer signature over Mobile Security Objects (MSO)
        CBORPairList document = extractDocument(mdoc);
        COSESign1 issuerAuth = extractIssuerAuth(document);
        verifyIssuerSignature(issuerAuth, truststoreProvider);

        // Verify device key binding
        CBORPairList mso = (CBORPairList) CborUtil.unwrap(issuerAuth.getPayload());
        verifyDeviceKeyBinding(document, mso, opts);

        // Verify that presented claims are protected by digests in MSO
        CBORPairList namespaces = extractNamespaces(document);
        NamespacedClaims claims = verifyMsoDigests(namespaces, mso);

        // Verify validity info of presentation in MSO
        verifyValidityInfo(mso, opts);

        // Enforce presentation requirements if provided
        if (presentationRequirements != null) {
            JsonNode claimsJson = JsonSerialization.writeValueAsNode(claims.namespaces());
            presentationRequirements.checkIfSatisfiedBy(claimsJson);
        }
    }

    /**
     * Verify device response status.
     */
    private static void verifyResponseStatus(CBORPairList mdoc) throws VerificationException {
        var status = (CBORInteger) mdoc.findByKey(MdocConstants.L_STATUS).getValue();
        if (!MdocConstants.V_STATUS_OK.equals(status.getValue())) {
            throw new VerificationException(
                    String.format("mDoc response status is not OK: status=%s", status.getValue()));
        }
    }

    /**
     * Verify issuer signature over Mobile Security Objects.
     *
     * <p>The X.5C chain attached to the issuer signature is PKIX-validated against the
     * provided truststore before its leaf public key is used to verify the COSE signature.
     */
    private void verifyIssuerSignature(COSESign1 issuerAuth, TruststoreProvider truststoreProvider)
            throws VerificationException {
        List<X509Certificate> x5cChain = CborUtil.extractX5Chain(issuerAuth);
        X509Certificate[] validatedChain = PKIXVerificationUtil.validateChain(x5cChain, truststoreProvider);

        try {
            X509Certificate leaf = validatedChain[0];
            if (!new COSEVerifier(leaf.getPublicKey()).verify(issuerAuth)) {
                throw new COSEException("COSE signature verification failed");
            }
        } catch (COSEException e) {
            throw new VerificationException("Issuer signature could not be verified", e);
        }
    }

    /**
     * Verify device key binding
     */
    private void verifyDeviceKeyBinding(CBORPairList document, CBORPairList mso, MdocVerificationOpts opts)
            throws VerificationException {
        COSESign1 deviceSignature = extractDeviceSignature(document);
        COSEKey deviceKey = extractDeviceKey(mso);

        try {
            // First attempt verification with session transcript computed as per OpenID4VP spec
            CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_OID4VPSpec(opts);
            verifyDeviceKeyBinding(document, sessionTranscript, deviceSignature, deviceKey);
        } catch (VerificationException e) {
            // If that fails, attempt verification with session transcript computed as per ISO spec
            logger.debugf(
                    e,
                    "Device key binding verification failed with OpenID4VP session transcript. Re-trying with ISO spec session transcript.");
            CBORItemList sessionTranscript = OID4VPSessionTranscript.computeSessionTranscript_ISOSpec(opts);
            verifyDeviceKeyBinding(document, sessionTranscript, deviceSignature, deviceKey);
        }
    }

    /**
     * Verify device key binding (with session transcript).
     */
    private void verifyDeviceKeyBinding(
            CBORPairList document, CBORItemList sessionTranscript, COSESign1 deviceSignature, COSEKey deviceKey)
            throws VerificationException {
        CBORItemList deviceAuthentication = new CBORItemList(
                new CBORString(MdocConstants.L_DEVICE_AUTHENTICATION),
                sessionTranscript,
                extractDocType(document),
                extractDeviceNamespaces(document));

        CBORTaggedItem payload = CborUtil.wrap(deviceAuthentication.encode());
        COSESign1 undetachedDeviceSignature = CborUtil.undetachCOSESign1(deviceSignature, payload);

        try {
            if (!new COSEVerifier(deviceKey.createPublicKey()).verify(undetachedDeviceSignature)) {
                throw new COSEException("COSE signature verification failed");
            }
        } catch (COSEException e) {
            throw new VerificationException("Device signature could not be verified", e);
        }
    }

    /**
     * Verify that presented claims are protected by digests in MSO
     */
    private NamespacedClaims verifyMsoDigests(CBORPairList namespaces, CBORPairList mso) throws VerificationException {
        var digestAlgorithm =
                (CBORString) mso.findByKey(MdocConstants.L_DIGEST_ALG).getValue();
        var valueDigests =
                (CBORPairList) mso.findByKey(MdocConstants.L_VALUE_DIGESTS).getValue();
        MessageDigest digester = verifyDigestAlgorithm(digestAlgorithm.getValue());

        // We'll also collect the claims in a map for subsequent presentation requirements verification
        Map<String, Map<String, Object>> nsClaims = new HashMap<>();

        // Run digest integrity verification for each namespace
        for (CBORPair namespace : namespaces.getPairs()) {
            var namespaceKey = CborUtil.asString(namespace.getKey());
            var elements = (CBORItemList) namespace.getValue();
            var digests = Optional.ofNullable(valueDigests.findByKey(namespaceKey))
                    .map(p -> (CBORPairList) p.getValue())
                    .orElse(null);

            if (!elements.getItems().isEmpty() && digests == null) {
                throw new VerificationException(
                        String.format("No value digests matching namespace: %s", namespace.getKey()));
            }

            // Run digest integrity verification for each element under the namespace
            Map<String, Object> claims = new HashMap<>();
            for (CBORItem element : elements.getItems()) {
                var unwrapped = (CBORPairList) CborUtil.unwrap(element);
                var digestId = (CBORInteger)
                        unwrapped.findByKey(MdocConstants.L_DIGEST_ID).getValue();

                var digest = Optional.ofNullable(digests)
                        .map(p -> p.findByKey(digestId.getValue()))
                        .map(CBORPair::getValue)
                        .orElse(null);

                if (!(digest instanceof CBORByteArray digestArray)
                        || !Arrays.equals(digestArray.getValue(), digester.digest(element.encode()))) {
                    throw new VerificationException(String.format("Digest mismatch for digestId=%s", digestId));
                }

                // Collect the claim for subsequent enforcement of presentation requirements
                try {
                    var elementIdentifier = (CBORString) unwrapped
                            .findByKey(MdocConstants.L_ELEMENT_IDENTIFIER)
                            .getValue();
                    var elementValue =
                            unwrapped.findByKey(MdocConstants.L_ELEMENT_VALUE).getValue();
                    claims.put(elementIdentifier.getValue(), new CBORParser(elementValue.encode()).next());
                } catch (IOException e) {
                    throw new VerificationException(
                            String.format("Failed to parse value of element with digestId=%s", digestId), e);
                }
            }
            nsClaims.put(namespaceKey, claims);
        }

        // Bubble up collected claims
        return new NamespacedClaims(nsClaims);
    }

    /**
     * Verify digest algorithm is one of the allowed options.
     */
    private MessageDigest verifyDigestAlgorithm(String digestAlg) throws VerificationException {
        if (!allowedDigestAlgs.contains(digestAlg.toUpperCase())) {
            throw new VerificationException(String.format(
                    "Invalid digest algorithm: %s. Must be one of %s",
                    digestAlg, JsonSerialization.valueAsString(allowedDigestAlgs)));
        }

        try {
            return MessageDigest.getInstance(digestAlg);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Verify validity info of presentation in MSO.
     */
    private void verifyValidityInfo(CBORPairList mso, MdocVerificationOpts opts) throws VerificationException {
        var info = (CBORPairList) mso.findByKey(MdocConstants.L_VALIDITY_INFO).getValue();
        var signed = (CBORString) info.findByKey(MdocConstants.L_SIGNED).getValue();
        var validFrom = (CBORString) info.findByKey(MdocConstants.L_VALID_FROM).getValue();
        var validUntil =
                (CBORString) info.findByKey(MdocConstants.L_VALID_UNTIL).getValue();

        try {
            opts.verifyValidityInfo(
                    Instant.parse(signed.getValue()).getEpochSecond(),
                    Instant.parse(validFrom.getValue()).getEpochSecond(),
                    Instant.parse(validUntil.getValue()).getEpochSecond());
        } catch (DateTimeParseException e) {
            throw new VerificationException("Failure parsing validity information as datetime", e);
        }
    }

    private static CBORPairList extractDocument(CBORPairList root) throws VerificationException {
        var documents = (CBORItemList) root.findByKey(MdocConstants.L_DOCUMENTS).getValue();
        if (documents.getItems().size() != 1) {
            // A single document is expected.
            // Request for multiple documents are satisfiable by the OpenID4VP response map.
            throw new VerificationException(String.format(
                    "Expected 1 document but received %d", documents.getItems().size()));
        }

        return (CBORPairList) documents.getItems().getFirst();
    }

    private static CBORString extractDocType(CBORPairList document) {
        return (CBORString) document.findByKey(MdocConstants.L_DOC_TYPE).getValue();
    }

    private static CBORPairList extractNamespaces(CBORPairList document) {
        var issuerSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();
        return (CBORPairList)
                issuerSigned.findByKey(MdocConstants.L_NAME_SPACES).getValue();
    }

    private static CBORTaggedItem extractDeviceNamespaces(CBORPairList document) {
        var deviceSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue();
        return (CBORTaggedItem)
                deviceSigned.findByKey(MdocConstants.L_NAME_SPACES).getValue();
    }

    private static COSESign1 extractIssuerAuth(CBORPairList document) throws VerificationException {
        var issuerSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();
        var issuerAuth = (CBORItemList)
                issuerSigned.findByKey(MdocConstants.L_ISSUER_AUTH).getValue();

        try {
            return COSESign1.build(issuerAuth);
        } catch (COSEException e) {
            throw new VerificationException("Failure parsing issuerAuth as COSE_Sign1", e);
        }
    }

    private static COSEKey extractDeviceKey(CBORPairList mso) throws VerificationException {
        var deviceKeyInfo =
                (CBORPairList) mso.findByKey(MdocConstants.L_DEVICE_KEY_INFO).getValue();
        var deviceKey = deviceKeyInfo.findByKey(MdocConstants.L_DEVICE_KEY).getValue();

        try {
            return COSEKey.build(deviceKey);
        } catch (COSEException e) {
            throw new VerificationException("Failure parsing deviceKey as COSEKey", e);
        }
    }

    private static COSESign1 extractDeviceSignature(CBORPairList document) throws VerificationException {
        var deviceSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_DEVICE_SIGNED).getValue();
        var deviceAuth = (CBORPairList)
                deviceSigned.findByKey(MdocConstants.L_DEVICE_AUTH).getValue();
        var deviceSignature = deviceAuth.findByKey(MdocConstants.L_DEVICE_SIGNATURE);

        if (deviceSignature == null) {
            throw new VerificationException("Device key binding verification failed: missing device signature");
        }

        try {
            return COSESign1.build(deviceSignature.getValue());
        } catch (COSEException e) {
            throw new VerificationException("Failure parsing deviceSignature as COSE_Sign1", e);
        }
    }
}
