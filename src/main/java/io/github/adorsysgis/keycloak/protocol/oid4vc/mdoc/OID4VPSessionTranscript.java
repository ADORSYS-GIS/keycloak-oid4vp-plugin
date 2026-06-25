package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORString;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * Computes OpenID4VP session transcript for replay protection in mDoc presentation.
 * <br>
 * Two algorithms are in use:
 *   one defined by the OpenID4VP spec (OpenID4VP 1.0 - B.2.6);
 *   the other defined by the ISO spec (ISO/IEC TS 18013-7:2025 - B.4.4).
 */
public class OID4VPSessionTranscript {

    private OID4VPSessionTranscript() {}

    /**
     * Computes OpenID4VP session transcript as per OpenID4VP 1.0 - B.2.6.
     *
     * @param clientId             `client_id` from OpenID4VP request object
     * @param oid4vpNonce          `nonce` from OpenID4VP request object
     * @param jwkThumbprint        The SHA-256 Thumbprint (as defined in [RFC7638]) of the JWK advertised in the
     *                             OpenID4VP request object for response encryption. If none, null.
     * @param responseUri          `response_uri` from OpenID4VP request object
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscr">
     *     Handover and SessionTranscript Definitions</a>
     */
    public static CBORItemList computeSessionTranscript_OID4VPSpec(
            String clientId, String oid4vpNonce, byte[] jwkThumbprint, String responseUri) {
        CBORItem jwkThumbprintCbor = jwkThumbprint != null && jwkThumbprint.length > 0
                ? new CBORByteArray(jwkThumbprint)
                : CBORNull.INSTANCE;

        CBORItemList handoverInfo = new CBORItemList(
                new CBORString(clientId), new CBORString(oid4vpNonce), jwkThumbprintCbor, new CBORString(responseUri));

        byte[] handoverInfoHash = DigestUtils.sha256(handoverInfo.encode());

        CBORItemList handover = new CBORItemList(
                new CBORString(MdocConstants.L_OPENID4VP_HANDOVER), new CBORByteArray(handoverInfoHash));

        return computeSessionTranscript(handover);
    }

    /**
     * Computes OpenID4VP session transcript as per ISO/IEC TS 18013-7:2025 - B.4.4.
     *
     * @param mdocGeneratedNonce   A nonce generated wallet-side. Set base64URL-encoded in the `apu` header of the
     *                             JWE encrypted OpenID4VP response.
     * @param clientId             `client_id` from OpenID4VP request object
     * @param responseUri          `response_uri` from OpenID4VP request object
     * @param oid4vpNonce          `nonce` from OpenID4VP request object
     */
    public static CBORItemList computeSessionTranscript_ISOSpec(
            String mdocGeneratedNonce, String clientId, String responseUri, String oid4vpNonce) {
        byte[] clientIdHash = DigestUtils.sha256(
                new CBORItemList(new CBORString(clientId), new CBORString(mdocGeneratedNonce)).encode());

        byte[] responseUriHash = DigestUtils.sha256(
                new CBORItemList(new CBORString(responseUri), new CBORString(mdocGeneratedNonce)).encode());

        CBORItemList handover = new CBORItemList(
                new CBORByteArray(clientIdHash), new CBORByteArray(responseUriHash), new CBORString(oid4vpNonce));

        return computeSessionTranscript(handover);
    }

    private static CBORItemList computeSessionTranscript(CBORItemList handover) {
        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }
}
