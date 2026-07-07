package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORByteArray;
import com.authlete.cbor.CBORItem;
import com.authlete.cbor.CBORItemList;
import com.authlete.cbor.CBORNull;
import com.authlete.cbor.CBORString;
import org.apache.commons.codec.digest.DigestUtils;
import org.keycloak.utils.StringUtil;

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
     *  @param opts Handover options for mDoc verification
     *
     * @see <a href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-handover-and-sessiontranscr">
     *     Handover and SessionTranscript Definitions</a>
     */
    public static CBORItemList computeSessionTranscript_OID4VPSpec(MdocVerificationOpts opts) {
        String clientId = requireNonNull(opts.getClientId(), "client_id");
        String nonce = requireNonNull(opts.getOid4vpNonce(), "nonce");
        String responseUri = requireNonNull(opts.getResponseUri(), "response_uri");

        byte[] thumbprint = opts.getJwkThumbprint();
        CBORItem jwkThumbprintCbor =
                thumbprint != null && thumbprint.length > 0 ? new CBORByteArray(thumbprint) : CBORNull.INSTANCE;

        CBORItemList handoverInfo = new CBORItemList(
                new CBORString(clientId), new CBORString(nonce), jwkThumbprintCbor, new CBORString(responseUri));

        byte[] handoverInfoHash = DigestUtils.sha256(handoverInfo.encode());

        CBORItemList handover = new CBORItemList(
                new CBORString(MdocConstants.L_OPENID4VP_HANDOVER), new CBORByteArray(handoverInfoHash));

        return computeSessionTranscript(handover);
    }

    /**
     * Computes OpenID4VP session transcript as per ISO/IEC TS 18013-7:2025 - B.4.4.
     *
     * @param opts Handover options for mDoc verification
     */
    public static CBORItemList computeSessionTranscript_ISOSpec(MdocVerificationOpts opts) {
        String mdocGeneratedNonce = requireNonNull(opts.getMdocGeneratedNonce(), "mdoc_generated_nonce");
        String clientId = requireNonNull(opts.getClientId(), "client_id");
        String nonce = requireNonNull(opts.getOid4vpNonce(), "nonce");
        String responseUri = requireNonNull(opts.getResponseUri(), "response_uri");

        byte[] clientIdHash = DigestUtils.sha256(
                new CBORItemList(new CBORString(clientId), new CBORString(mdocGeneratedNonce)).encode());

        byte[] responseUriHash = DigestUtils.sha256(
                new CBORItemList(new CBORString(responseUri), new CBORString(mdocGeneratedNonce)).encode());

        CBORItemList handover = new CBORItemList(
                new CBORByteArray(clientIdHash), new CBORByteArray(responseUriHash), new CBORString(nonce));

        return computeSessionTranscript(handover);
    }

    private static CBORItemList computeSessionTranscript(CBORItemList handover) {
        return new CBORItemList(CBORNull.INSTANCE, CBORNull.INSTANCE, handover);
    }

    private static String requireNonNull(String value, String name) {
        if (StringUtil.isBlank(value)) {
            throw new IllegalArgumentException(String.format("Cannot compute handover: '%s' must not be null", name));
        }

        return value;
    }
}
