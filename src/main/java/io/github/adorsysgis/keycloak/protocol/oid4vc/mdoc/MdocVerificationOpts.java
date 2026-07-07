package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import static org.keycloak.OID4VCConstants.CLAIM_NAME_EXP;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_IAT;
import static org.keycloak.OID4VCConstants.CLAIM_NAME_NBF;

import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.ClaimVerifier;
import org.keycloak.util.JsonSerialization;

/**
 * Options for mDoc device response verification.
 */
public class MdocVerificationOpts extends ClaimVerifier {

    /**
     * For OpenID4VP handover - `client_id` from OpenID4VP request object.
     */
    private final String clientId;

    /**
     * For OpenID4VP handover - `nonce` from OpenID4VP request object.
     */
    private final String oid4vpNonce;

    /**
     * For OpenID4VP handover - Nonce generated wallet-side as per mDoc spec.
     * Then set base64URL-encoded in the `apu` header of the JWE encrypted OpenID4VP response.
     */
    private final String mdocGeneratedNonce;

    /**
     * For OpenID4VP handover - `response_uri` from OpenID4VP request object.
     */
    private final String responseUri;

    /**
     * For OpenID4VP handover - The SHA-256 Thumbprint (as defined in [RFC7638]) of the JWK
     * advertised in the OpenID4VP request object for response encryption. If none, null.
     */
    private final byte[] jwkThumbprint;

    /**
     * Whether to allow falling back to the ISO-spec session transcript
     * (ISO/IEC TS 18013-7:2025 - B.4.4) when verification with the OpenID4VP-spec
     * session transcript (OpenID4VP 1.0 - B.2.6) fails.
     */
    private final boolean fallbackToIsoSpecSessionTranscript;

    private MdocVerificationOpts(
            List<ClaimVerifier.Predicate<ObjectNode>> contentVerifiers,
            String clientId,
            String oid4vpNonce,
            String mdocGeneratedNonce,
            String responseUri,
            byte[] jwkThumbprint,
            boolean fallbackToIsoSpecSessionTranscript) {
        super(List.of(), contentVerifiers);
        this.clientId = clientId;
        this.oid4vpNonce = oid4vpNonce;
        this.mdocGeneratedNonce = mdocGeneratedNonce;
        this.responseUri = responseUri;
        this.jwkThumbprint = jwkThumbprint;
        this.fallbackToIsoSpecSessionTranscript = fallbackToIsoSpecSessionTranscript;
    }

    public String getClientId() {
        return clientId;
    }

    public String getOid4vpNonce() {
        return oid4vpNonce;
    }

    public byte[] getJwkThumbprint() {
        return jwkThumbprint;
    }

    public String getResponseUri() {
        return responseUri;
    }

    public String getMdocGeneratedNonce() {
        return mdocGeneratedNonce;
    }

    public boolean fallbackToIsoSpecSessionTranscript() {
        return fallbackToIsoSpecSessionTranscript;
    }

    /**
     * Verifies validity information of mDoc device response
     *
     * @param signed     The timestamp at which the mDoc device response was signed
     * @param validFrom  The timestamp from which the mDoc device response is valid
     * @param validUntil The timestamp until which the mDoc device response is valid
     */
    public void verifyValidityInfo(long signed, long validFrom, long validUntil) throws VerificationException {
        var header = JsonSerialization.createObjectNode();
        var payload = JsonSerialization.createObjectNode();

        payload.put(CLAIM_NAME_IAT, signed);
        payload.put(CLAIM_NAME_NBF, validFrom);
        payload.put(CLAIM_NAME_EXP, validUntil);

        try {
            verifyClaims(header, payload);
        } catch (VerificationException e) {
            throw new VerificationException(
                    String.format(
                            "Validity information verification failed. signed=%d validFrom=%d validUntil=%d",
                            signed, validFrom, validUntil),
                    e);
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(Integer clockSkew) {
        return new Builder(clockSkew);
    }

    public static class Builder extends ClaimVerifier.Builder {

        private String clientId;
        private String oid4vpNonce;
        private String mdocGeneratedNonce;
        private String responseUri;
        private byte[] jwkThumbprint;
        private boolean fallbackToIsoSpecSessionTranscript;

        private Builder() {
            super();
        }

        private Builder(Integer clockSkew) {
            super(clockSkew);
        }

        public Builder withClientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder withOid4vpNonce(String oid4vpNonce) {
            this.oid4vpNonce = oid4vpNonce;
            return this;
        }

        public Builder withMdocGeneratedNonce(String mdocGeneratedNonce) {
            this.mdocGeneratedNonce = mdocGeneratedNonce;
            return this;
        }

        public Builder withResponseUri(String responseUri) {
            this.responseUri = responseUri;
            return this;
        }

        public Builder withJwkThumbprint(byte[] jwkThumbprint) {
            this.jwkThumbprint = jwkThumbprint;
            return this;
        }

        public Builder withFallbackToIsoSpecSessionTranscript(boolean fallbackToIsoSpecSessionTranscript) {
            this.fallbackToIsoSpecSessionTranscript = fallbackToIsoSpecSessionTranscript;
            return this;
        }

        public Builder withAllowedMaxAge(Integer allowedMaxAge) {
            return (Builder) super.withIatCheck(allowedMaxAge, false);
        }

        @Override
        public MdocVerificationOpts build() {
            return new MdocVerificationOpts(
                    contentVerifiers,
                    clientId,
                    oid4vpNonce,
                    mdocGeneratedNonce,
                    responseUri,
                    jwkThumbprint,
                    fallbackToIsoSpecSessionTranscript);
        }
    }
}
