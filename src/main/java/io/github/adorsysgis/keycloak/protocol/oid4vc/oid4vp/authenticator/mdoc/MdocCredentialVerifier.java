package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.mdoc;

import static io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants.L_NAME_SPACES;

import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORPairList;
import com.authlete.cbor.CBORParser;
import com.authlete.cose.COSEException;
import com.authlete.cose.COSESign1;
import com.fasterxml.jackson.databind.JsonNode;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.CborUtil;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocConstants;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocEncodingException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocParser;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc.MdocVerificationOpts;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialFormat;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator.CredentialVerifier;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.ClientMetadata;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.RequestObject;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.model.dto.AuthorizationContext;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement.ClaimReference;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.trust.TrustAnchorProvider;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.ReferencedTokenValidator.ReferencedTokenValidationException;
import io.github.adorsysgis.keycloak.protocol.oid4vc.tokenstatus.http.StatusListJwtFetcher;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
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

        new MdocVerificationContext(token).verifyPresentation(opts, requirements, truststore);

        if (authReqs.shouldEnforceRevocationStatus()) {
            try {
                JsonNode msoPayload = extractMsoPayload(token);
                tokenStatusValidator.validate(msoPayload);
            } catch (ReferencedTokenValidationException e) {
                throw new VerificationException(
                        String.format(
                                "Token status verification failed for credential to requirement '%s'",
                                credential.getId()),
                        e);
            }
        }

        return payloadRef.get().get(L_NAME_SPACES);
    }

    static JsonNode extractMsoPayload(String mdocToken) throws VerificationException {
        try {
            var response = MdocParser.parseBase64Url(mdocToken);
            var documents = findRequired(response, MdocConstants.L_DOCUMENTS, CBORItemList.class);
            var document = firstDocument(documents);
            var issuerSigned = findRequired(document, MdocConstants.L_ISSUER_SIGNED, CBORPairList.class);
            var issuerAuthList = findRequired(issuerSigned, MdocConstants.L_ISSUER_AUTH, CBORItemList.class);
            var payload = CborUtil.unwrap(COSESign1.build(issuerAuthList).getPayload());
            return JsonSerialization.mapper.valueToTree(new CBORParser(payload.encode()).next());
        } catch (MdocEncodingException | COSEException | IOException e) {
            throw new VerificationException("Failed to extract MSO payload for status verification", e);
        }
    }

    private static <T extends CBORItem> T findRequired(CBORPairList parent, String key, Class<T> type)
            throws VerificationException {
        var entry = parent.findByKey(key);
        if (entry == null || !type.isInstance(entry.getValue())) {
            throw new VerificationException("mDoc response has invalid or missing '" + key + "'");
        }
        return type.cast(entry.getValue());
    }

    private static CBORPairList firstDocument(CBORItemList documents) throws VerificationException {

        var items = documents.getItems();

        if (items.isEmpty()) {
            throw new VerificationException("mDoc response contains no documents");
        }

        var first = items.getFirst();

        if (!(first instanceof CBORPairList doc)) {
            throw new VerificationException("mDoc document has invalid format");
        }

        return doc;
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
