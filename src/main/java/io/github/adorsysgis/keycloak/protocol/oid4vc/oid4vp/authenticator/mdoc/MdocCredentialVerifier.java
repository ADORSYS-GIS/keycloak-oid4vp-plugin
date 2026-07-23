package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_NAME_SPACES;

import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPair;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORString;
import com.authlete.cbor.CBORTaggedItem;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.CborUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.OID4VPAuthenticator;
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
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.sdjwt.consumer.PresentationRequirements;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JWKSUtils;
import org.keycloak.util.JsonSerialization;
import org.keycloak.utils.StringUtil;

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
            CredentialRequirement credential,
            String token,
            boolean requireCryptographicHolderBinding)
            throws VerificationException {

        MdocAuthRequirements authReqs = new MdocAuthRequirements(context.getAuthenticatorConfig(), credential);

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
            validateTransactionData(context.getAuthenticationSession(), verificationContext);
        }

        return payloadRef.get().get(L_NAME_SPACES);
    }

    /**
     * Validates {@code transaction_data_hashes} contained in
     * {@code DeviceSigned.nameSpaces} against the verifier's
     * {@code transaction_data} request.
     */
    void validateTransactionData(AuthenticationSessionModel authSession, MdocVerificationContext verificationContext)
            throws VerificationException {
        String wireJson = authSession.getAuthNote(OID4VPAuthenticator.TRANSACTION_DATA_WIRE_KEY);
        if (StringUtil.isBlank(wireJson)) {
            return;
        }

        List<String> transactionDataWire;
        try {
            transactionDataWire = JsonSerialization.readValue(wireJson, new TypeReference<>() {});
        } catch (IOException e) {
            throw new VerificationException("Invalid transaction_data session state", e);
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

        // First pass: find the namespace containing transaction_data_hashes
        ArrayNode hashes = null;
        String hashesNamespace = null;

        for (CBORPair nsPair : nsMap.getPairs()) {
            if (nsPair == null || !(nsPair.getValue() instanceof CBORPairList itemsMap)) {
                continue;
            }
            var hashesPair = itemsMap.findByKey(TransactionDataValidator.TRANSACTION_DATA_HASHES_CLAIM);
            if (hashesPair != null) {
                if (hashesNamespace != null) {
                    throw new VerificationException("transaction_data_hashes must not appear in multiple namespaces");
                }
                hashes = extractHashesArray(hashesPair.getValue());
                hashesNamespace = CborUtil.asString(nsPair.getKey());
            }
        }

        if (hashes == null) {
            return null;
        }

        // Second pass: read alg only from the hashes namespace; reject alg in other namespaces
        String hashesAlg = null;

        for (CBORPair nsPair : nsMap.getPairs()) {
            if (nsPair == null || !(nsPair.getValue() instanceof CBORPairList itemsMap)) {
                continue;
            }
            String nsName = CborUtil.asString(nsPair.getKey());
            var algPair = itemsMap.findByKey(TransactionDataValidator.TRANSACTION_DATA_HASHES_ALG_CLAIM);
            if (algPair == null) {
                continue;
            }
            if (!nsName.equals(hashesNamespace)) {
                throw new VerificationException(
                        "transaction_data_hashes_alg must not appear outside the namespace containing transaction_data_hashes");
            }
            hashesAlg = extractAlgString(algPair.getValue());
        }

        // Verify the namespace is authorized in the MSO's KeyAuthorizations
        verifyNamespaceIsAuthorized(verificationContext.getVerifiedMsoPayload(), hashesNamespace);

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

    private static void verifyNamespaceIsAuthorized(JsonNode mso, String namespace) throws VerificationException {
        JsonNode dki = mso.get(MdocConstants.L_DEVICE_KEY_INFO);
        if (dki == null) {
            throw new VerificationException("MSO is missing deviceKeyInfo");
        }
        JsonNode keyAuth = dki.get("keyAuthorizations");
        if (keyAuth == null) {
            throw new VerificationException("MSO deviceKeyInfo is missing keyAuthorizations");
        }
        JsonNode authorizedNs = keyAuth.get("nameSpaces");
        if (authorizedNs == null || !authorizedNs.isArray()) {
            throw new VerificationException("MSO keyAuthorizations is missing authorized nameSpaces");
        }
        boolean authorized = false;
        for (JsonNode ns : authorizedNs) {
            if (ns.asText().equals(namespace)) {
                authorized = true;
                break;
            }
        }
        if (!authorized) {
            throw new VerificationException(
                    "Namespace '" + namespace + "' is not authorized for transaction_data_hashes in the MSO");
        }
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
