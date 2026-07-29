package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_NAME_SPACES;

import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.CborUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.config.AuthRequirements;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.utils.TransactionDataValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;

/**
 * {@link CredentialVerifier} implementation backing verification of {@code mso_mdoc}
 * (ISO/IEC 18013-5) credentials presented via OpenID4VP.
 *
 * <p>Owns the mDoc-specific verification entry points (issuer signature, device key
 * binding, MSO digest integrity, validity info, claim requirements, trust policy).
 */
public class MdocCredentialVerifier implements CredentialVerifier {

    private final ReferencedTokenValidator tokenStatusValidator;

    public MdocCredentialVerifier(StatusListJwtFetcher statusListJwtFetcher) {
        this.tokenStatusValidator = new ReferencedTokenValidator(statusListJwtFetcher);
    }

    @Override
    public CredentialFormat format() {
        return CredentialFormat.MSO_MDOC;
    }

    @Override
    public JsonNode verifyCredential(
            AuthenticationFlowContext context,
            AuthorizationContext authorizationContext,
            AuthRequirements authRequirements,
            CredentialRequirement credential,
            String token)
            throws VerificationException {

        MdocAuthRequirements authReqs = new MdocAuthRequirements(authRequirements, credential);

        TrustAnchorProvider truststore = TrustedProviderResolver.resolve(context.getSession(), credential);

        RequestObject requestObject = authorizationContext.getRequestObject();

        byte[] jwkThumbprint = computeJwkThumbprint(requestObject);
        String mdocGeneratedNonce = authorizationContext.getResponseApuNonce();

        MdocVerificationOpts opts = authReqs.getMdocVerificationOpts(
                requestObject.getClientId(),
                requestObject.getNonce(),
                requestObject.getResponseUri(),
                jwkThumbprint,
                mdocGeneratedNonce);

        AtomicReference<JsonNode> payloadRef = new AtomicReference<>();
        PresentationRequirements requirements = payload -> {
            payloadRef.set(payload);
            authReqs.getPresentationRequirements().checkIfSatisfiedBy(payload);
        };

        MdocVerificationContext verificationContext = new MdocVerificationContext(token);
        verificationContext.verifyPresentation(opts, requirements, truststore);

        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                // Status is stored in the MSO payload per IETF Token Status List §Referenced Token
                // (https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-11.html#name-referenced-token-in-cose)
                // and MATTR docs
                // (https://learn.mattr.global/docs/holding/credential-claiming-guides/revocation-status-check).
                tokenStatusValidator.validate(verificationContext.getVerifiedMsoPayload());
            } catch (ReferencedTokenValidationException e) {
                throw new VerificationException(
                        String.format(
                                "Token status verification failed for credential to requirement '%s'",
                                credential.getId()),
                        e);
            }
        }

        if (credential.isPrimary()) {
            validateTransactionData(authorizationContext, verificationContext);
        }

        return payloadRef.get().get(L_NAME_SPACES);
    }

    /**
     * Validates {@code transaction_data_hashes} contained in
     * {@code DeviceSigned.nameSpaces} against the verifier's
     * {@code transaction_data} request.
     */
    void validateTransactionData(AuthorizationContext authorizationContext, MdocVerificationContext verificationContext)
            throws VerificationException {
        List<String> transactionDataWire =
                authorizationContext.getRequestObject().getTransactionData();
        if (transactionDataWire == null || transactionDataWire.isEmpty()) {
            return;
        }

        ObjectNode hashesPayload = extractTransactionDataHashes(verificationContext);
        if (hashesPayload == null) {
            throw new VerificationException(
                    "Device namespaces must contain transaction_data_hashes when transaction_data is requested");
        }

        try {
            TransactionDataValidator.validate(transactionDataWire, hashesPayload);
        } catch (IllegalArgumentException e) {
            throw new VerificationException("transaction_data_hashes validation failed", e);
        }
    }

    /** Builds an ObjectNode from DeviceSigned.nameSpaces for TransactionDataValidator.
     *  Returns null when transaction_data_hashes is absent.
     *  Checks that the namespace is authorized in the MSO's KeyAuthorizations per ISO 18013-5.
     */
    private static ObjectNode extractTransactionDataHashes(MdocVerificationContext verificationContext)
            throws VerificationException {
        CBORTaggedItem nameSpacesTagged = verificationContext.getDeviceNameSpaces();
        CBORItem unwrapped = CborUtil.unwrap(nameSpacesTagged);

        if (!(unwrapped instanceof CBORPairList nsMap)) {
            throw new VerificationException("DeviceSigned.nameSpaces is not a valid CBOR map");
        }

        // Single pass: collect both hashes and alg while checking for duplicates and cross-namespace violations
        ArrayNode hashes = null;
        String hashesNamespace = null;
        String hashesAlg = null;
        String hashAlgNamespace = null;

        for (CBORPair nsPair : nsMap.getPairs()) {
            if (nsPair == null || !(nsPair.getValue() instanceof CBORPairList itemsMap)) {
                continue;
            }
            String nsName = CborUtil.asString(nsPair.getKey());

            var hashesPair = itemsMap.findByKey(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM);
            if (hashesPair != null) {
                if (hashesNamespace != null) {
                    throw new VerificationException("transaction_data_hashes must not appear in multiple namespaces");
                }
                hashes = extractHashesArray(hashesPair.getValue());
                hashesNamespace = nsName;
            }

            var algPair = itemsMap.findByKey(TransactionDataValidator.TRANSACTION_DATA_HASHES_ALG_CLAIM);
            if (algPair != null) {
                if (hashAlgNamespace != null) {
                    throw new VerificationException(
                            "transaction_data_hashes_alg must not appear in multiple namespaces");
                }
                hashAlgNamespace = nsName;
                hashesAlg = extractAlgString(algPair.getValue());
            }
        }

        if (hashes == null) {
            return null;
        }

        if (hashAlgNamespace != null && !hashAlgNamespace.equals(hashesNamespace)) {
            throw new VerificationException(
                    "transaction_data_hashes_alg must not appear outside the namespace containing transaction_data_hashes");
        }

        // Verify the namespace or elements are authorized in the MSO's KeyAuthorizations
        verifyKeyAuthorization(
                verificationContext.getVerifiedMsoPayload(),
                hashesNamespace,
                hashesAlg != null
                        ? List.of(
                                TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM,
                                TransactionDataValidator.TRANSACTION_DATA_HASHES_ALG_CLAIM)
                        : List.of(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM));

        ObjectNode result = JsonSerialization.mapper.createObjectNode();
        result.set(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM, hashes);
        if (hashesAlg != null) {
            result.put(TransactionDataValidator.TRANSACTION_DATA_HASHES_ALG_CLAIM, hashesAlg);
        }
        return result;
    }

    private static String extractAlgString(CBORItem value) throws VerificationException {
        if (value instanceof CBORString s) {
            return s.getValue();
        }
        if (value instanceof CBORItemList list
                && list.getItems().size() == 1
                && list.getItems().get(0) instanceof CBORString s) {
            return s.getValue();
        }
        throw new VerificationException("transaction_data_hashes_alg must be a string");
    }

    /**
     * Verifies that the device key is authorized for the given elements in the given namespace
     * {@code KeyAuthorizations}. Authorization can come via either:
     * <ul>
     *   <li>{@code nameSpaces[namespace]} — authorizes all elements in the namespace, or
     *   <li>{@code dataElements[namespace]} — authorizes only the listed {@code elementIds}.
     * </ul>
     */
    private static void verifyKeyAuthorization(JsonNode mso, String namespace, List<String> elementIds)
            throws VerificationException {
        JsonNode dki = mso.get(MdocConstants.L_DEVICE_KEY_INFO);
        if (dki == null) {
            throw new VerificationException("MSO is missing deviceKeyInfo");
        }
        JsonNode keyAuth = dki.get(MdocConstants.L_KEY_AUTHORIZATIONS);
        if (keyAuth == null) {
            throw new VerificationException("MSO deviceKeyInfo is missing keyAuthorizations");
        }
        // Check namespace-level authorization first
        JsonNode nameSpaces = keyAuth.get(MdocConstants.L_NAME_SPACES);
        if (nameSpaces != null && nameSpaces.isArray()) {
            for (JsonNode ns : nameSpaces) {
                if (ns.asText().equals(namespace)) {
                    return;
                }
            }
        }
        // Fall back to element-level authorization
        JsonNode dataElements = keyAuth.get(MdocConstants.L_DATA_ELEMENTS);
        if (dataElements != null && dataElements.isObject()) {
            JsonNode elements = dataElements.get(namespace);
            if (elements != null && elements.isArray()) {
                Set<String> existingIds = StreamSupport.stream(elements.spliterator(), false)
                        .map(JsonNode::asText)
                        .collect(Collectors.toSet());
                if (existingIds.containsAll(elementIds)) {
                    return;
                }
            }
        }
        throw new VerificationException(
                "Namespace '" + namespace + "' is not authorized for " + elementIds + " in the MSO");
    }

    // Converts a CBOR array of strings (or a single string) to a JSON ArrayNode.
    // Rejects non-string entries to prevent silent hash filtering.
    private static ArrayNode extractHashesArray(CBORItem value) throws VerificationException {
        ArrayNode hashes = JsonSerialization.mapper.createArrayNode();
        if (value instanceof CBORItemList list) {
            for (CBORItem hashItem : list.getItems()) {
                if (hashItem instanceof CBORString hashStr) {
                    hashes.add(hashStr.getValue());
                } else {
                    throw new VerificationException("transaction_data_hashes entries must be strings");
                }
            }
        } else if (value instanceof CBORString singleHash) {
            hashes.add(singleHash.getValue());
        } else {
            throw new VerificationException("transaction_data_hashes must be a string or array of strings");
        }
        return hashes;
    }

    /**
     * Computes the SHA-256 thumbprint (RFC 7638) of the JWK advertised in the OpenID4VP
     * request object for response encryption, Base64URL-decoded to raw bytes. Returns
     * {@code null} when the request object advertises no encryption JWK.
     */
    public static byte[] computeJwkThumbprint(RequestObject requestObject) {
        return Optional.ofNullable(requestObject.getClientMetadata())
                .map(ClientMetadata::getJwks)
                .map(JSONWebKeySet::getKeys)
                .filter(keys -> keys.length > 0)
                .map(keys -> keys[0])
                .map(JWKSUtils::computeThumbprint)
                .map(Base64Url::decode)
                .orElse(null);
    }

    @Override
    public String readClaim(JsonNode claims, String claimName) {
        return Optional.ofNullable(SimpleMdocPresentationDefinition.findClaim(ClaimReference.parse(claimName), claims))
                .filter(v -> !v.isNull())
                .map(JsonNode::asText)
                .orElse(null);
    }
}
