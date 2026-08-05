package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.dcql;

import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cose.constants.COSEAlgorithms;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.CborUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocParser;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Claim;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dcql.Credential;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.prex.MdocGenericFormat;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.keycloak.common.VerificationException;

/**
 * DCQL capability for {@code mso_mdoc} (ISO/IEC 18013-5) credentials.
 *
 * <p>Pre-validates the presented DeviceResponse document type and the presence of requested
 * namespace/data-element paths. Cryptographic, digest, validity, trust, and device-binding checks remain in the
 * mDoc credential verifier.
 *
 * <p>Contributes VP format metadata with COSE algorithm identifiers for
 * issuer authentication and device authentication per OpenID4VP Final 1.0
 * Appendix B.2.2.
 */
public final class MdocDcqlCredentialCapability implements DcqlCredentialCapability {

    @Override
    public String format() {
        return CredentialFormat.MSO_MDOC.getValue();
    }

    @Override
    public boolean supportsPresentationPreValidation() {
        return true;
    }

    @Override
    public void validatePresentation(Credential credential, String presentedToken) throws VerificationException {
        if (!format().equals(credential.getFormat())) {
            throw new VerificationException(
                    "Unsupported dcql_query credential format for presentation validation: " + credential.getFormat());
        }

        PresentedMdoc presentation = parsePresentation(presentedToken);
        String expectedDocType = credential.getMeta().getDoctypeValue();
        if (!Objects.equals(expectedDocType, presentation.docType())) {
            throw new VerificationException(
                    "Presented mDoc docType does not match meta.doctype_value: " + presentation.docType());
        }

        validateRequestedClaims(credential, presentation.claimPaths());
    }

    @Override
    public void contributeVpFormatsSupported(ClientMetadata.VpFormat vpFormat, List<String> signatureAlgorithms) {
        MdocGenericFormat format = new MdocGenericFormat();
        // `COSEAlgorithms.getValueByName` returns 0 (the reserved COSE algorithm) for JOSE names
        // it cannot map; advertising a reserved algorithm is misleading to wallets, so drop them.
        List<Integer> coseAlgorithms = signatureAlgorithms.stream()
                .map(COSEAlgorithms::getValueByName)
                .filter(value -> value != 0)
                .toList();
        format.setIssuerAuthAlgValues(coseAlgorithms);
        format.setDeviceAuthAlgValues(coseAlgorithms);
        vpFormat.setMsoMdoc(format);
    }

    private static PresentedMdoc parsePresentation(String presentedToken) throws VerificationException {
        CBORPairList deviceResponse;
        try {
            deviceResponse = MdocParser.parseBase64Url(presentedToken);
        } catch (MdocEncodingException e) {
            throw new IllegalArgumentException("Failed to parse presented mDoc device response", e);
        }

        CBORPair documentsEntry = deviceResponse.findByKey(MdocConstants.L_DOCUMENTS);
        if (documentsEntry == null) {
            throw new VerificationException("Presented mDoc response is missing the documents field");
        }

        CBORItemList documents = (CBORItemList) documentsEntry.getValue();
        if (documents.getItems().size() != 1) {
            throw new VerificationException("Presented mDoc response must contain exactly one document, but contained "
                    + documents.getItems().size());
        }

        CBORPairList document = (CBORPairList) documents.getItems().getFirst();
        String docType =
                ((CBORString) document.findByKey(MdocConstants.L_DOC_TYPE).getValue()).getValue();
        return new PresentedMdoc(docType, extractClaimPaths(document));
    }

    private static Set<ClaimPath> extractClaimPaths(CBORPairList document) {
        CBORPairList issuerSigned =
                (CBORPairList) document.findByKey(MdocConstants.L_ISSUER_SIGNED).getValue();
        CBORPair namespacesEntry = issuerSigned.findByKey(MdocConstants.L_NAME_SPACES);
        if (namespacesEntry == null) {
            return Set.of();
        }

        Set<ClaimPath> claimPaths = new HashSet<>();
        CBORPairList namespaces = (CBORPairList) namespacesEntry.getValue();
        for (CBORPair namespace : namespaces.getPairs()) {
            String namespaceIdentifier = CborUtil.asString(namespace.getKey());
            CBORItemList issuerSignedItems = (CBORItemList) namespace.getValue();
            for (CBORItem issuerSignedItem : issuerSignedItems.getItems()) {
                CBORPairList item = (CBORPairList) CborUtil.unwrap(issuerSignedItem);
                String elementIdentifier = ((CBORString) item.findByKey(MdocConstants.L_ELEMENT_IDENTIFIER)
                                .getValue())
                        .getValue();
                claimPaths.add(new ClaimPath(namespaceIdentifier, elementIdentifier));
            }
        }
        return Set.copyOf(claimPaths);
    }

    /**
     * Validates claim-path presence and claim-set alternatives. Claim {@code values} are intentionally not enforced:
     * OpenID4VP Final 1.0 defines them as a best-effort wallet privacy hint that verifiers must not treat as a
     * security control.
     */
    private static void validateRequestedClaims(Credential credential, Set<ClaimPath> presentedClaimPaths)
            throws VerificationException {
        List<Claim> claims = credential.getClaims();
        if (claims == null || claims.isEmpty()) {
            return;
        }

        List<List<String>> claimSets = credential.getClaimSets();
        if (claimSets == null || claimSets.isEmpty()) {
            for (Claim claim : claims) {
                if (!isPresented(claim, presentedClaimPaths)) {
                    throw new VerificationException(
                            "Presented mDoc does not satisfy DCQL claim path: " + claim.getPath());
                }
            }
            return;
        }

        boolean satisfiesAnyClaimSet = claimSets.stream()
                .anyMatch(option -> option.stream().allMatch(claimId -> claims.stream()
                        .filter(claim -> Objects.equals(claimId, claim.getId()))
                        .anyMatch(claim -> isPresented(claim, presentedClaimPaths))));
        if (!satisfiesAnyClaimSet) {
            throw new VerificationException("Presented mDoc does not satisfy any DCQL claim_sets option");
        }
    }

    private static boolean isPresented(Claim claim, Set<ClaimPath> presentedClaimPaths) {
        List<String> path = claim.getPath();
        return path != null
                && path.size() == 2
                && presentedClaimPaths.contains(new ClaimPath(path.getFirst(), path.get(1)));
    }

    private record PresentedMdoc(String docType, Set<ClaimPath> claimPaths) {}

    private record ClaimPath(String namespace, String elementIdentifier) {}
}
