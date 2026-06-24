package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORInteger;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSESign1;
import com.authlete.cose.COSEVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.util.CborUtil;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;
import org.keycloak.common.VerificationException;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sdjwt.vp.KeyBindingJwtVerificationOpts;
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
     * @param issuerVerifyingKeys             Verifying keys for validating issuerSigned components. The caller
     *                                        is responsible for establishing trust in these keys.
     * @param mDocVerificationOpts            Options to parameterize the mDoc verification.
     * @param presentationRequirements        If set, the presentation requirements will be enforced on the claims
     *                                        in the mDoc upon verification.
     * @throws VerificationException if verification failed
     */
    public void verifyPresentation(
            List<SignatureVerifierContext> issuerVerifyingKeys,
            KeyBindingJwtVerificationOpts mDocVerificationOpts,
            PresentationRequirements presentationRequirements)
            throws VerificationException {
        // Verify issuer signature over Mobile Security Objects (MSO)
        CBORPairList document = extractDocument(mdoc);
        COSESign1 issuerAuth = extractIssuerAuth(document);
        verifyIssuerSignature(issuerAuth, List.of());

        // Verify that presented claims are protected by digests in MSO
        CBORPairList namespaces = extractNamespaces(document);
        CBORPairList mso = (CBORPairList) CborUtil.unwrap(issuerAuth.getPayload());
        verifyMsoDigests(namespaces, mso);
    }

    /**
     * Verify issuer signature over Mobile Security Objects
     */
    private void verifyIssuerSignature(COSESign1 issuerAuth, List<X509Certificate> trustedCertificates)
            throws VerificationException {
        List<X509Certificate> x5chain = extractX5Chain(issuerAuth);
        if (x5chain == null || x5chain.isEmpty()) {
            throw new VerificationException("No X5C certificate attached to issuer signature");
        }

        // TODO: Enforce trust in X5C certificate chain

        try {
            X509Certificate verifier = x5chain.getLast();
            PublicKey pubKey = verifier.getPublicKey();
            if (!new COSEVerifier(pubKey).verify(issuerAuth)) {
                throw new COSEException("COSE signature verification failed");
            }
        } catch (COSEException e) {
            throw new VerificationException("Issuer signature could not be verified", e);
        }
    }

    /**
     * Verify that presented claims are protected by digests in MSO
     */
    private void verifyMsoDigests(CBORPairList namespaces, CBORPairList mso) throws VerificationException {
        var digestAlgorithm =
                (CBORString) mso.findByKey(MdocConstants.L_DIGEST_ALG).getValue();
        var valueDigests =
                (CBORPairList) mso.findByKey(MdocConstants.L_VALUE_DIGESTS).getValue();
        MessageDigest digester = verifyDigestAlgorithm(digestAlgorithm.getValue());

        // Run digest integrity verification for each namespace
        for (CBORPair namespace : namespaces.getPairs()) {
            var elements = (CBORItemList) namespace.getValue();
            var digests = Optional.ofNullable(valueDigests.findByKey(CborUtil.asString(namespace.getKey())))
                    .map(p -> (CBORPairList) p.getValue())
                    .orElse(null);

            if (!elements.getItems().isEmpty() && digests == null) {
                throw new VerificationException(
                        String.format("No value digests matching namespace: %s", namespace.getKey()));
            }

            // Run digest integrity verification for each element under the namespace
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
            }
        }
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

    private static CBORPairList extractNamespaces(CBORPairList document) {
        var issuerSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();
        return (CBORPairList)
                issuerSigned.findByKey(MdocConstants.L_NAME_SPACES).getValue();
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

    private List<X509Certificate> extractX5Chain(COSESign1 sign1) {
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
}
