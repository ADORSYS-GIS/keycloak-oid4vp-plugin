package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.cbor.CBORPairList;
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

    private MdocVerificationOpts(
            List<Predicate<ObjectNode>> headerVerifiers,
            List<ClaimVerifier.Predicate<ObjectNode>> contentVerifiers,
            String clientId,
            String oid4vpNonce,
            String mdocGeneratedNonce,
            String responseUri,
            byte[] jwkThumbprint) {
        super(headerVerifiers, contentVerifiers);
        this.clientId = clientId;
        this.oid4vpNonce = oid4vpNonce;
        this.mdocGeneratedNonce = mdocGeneratedNonce;
        this.responseUri = responseUri;
        this.jwkThumbprint = jwkThumbprint;
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

    public void verifyValidityInfo(CBORPairList validityInfo) throws VerificationException {
        var header = JsonSerialization.createObjectNode();
        var payload = JsonSerialization.createObjectNode();

        super.verifyClaims(header, payload);
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

        private Builder() {}

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

        public Builder withSignedAtCheck(boolean isCheckOptional) {
            return (Builder) super.withIatCheck(isCheckOptional);
        }

        public Builder withSignedAtCheck(Integer allowedMaxAge, boolean isCheckOptional) {
            return (Builder) super.withIatCheck(allowedMaxAge, isCheckOptional);
        }

        public Builder withValidFromCheck(boolean isCheckOptional) {
            return (Builder) super.withNbfCheck(isCheckOptional);
        }

        public Builder withValidUntil(boolean isCheckOptional) {
            return (Builder) super.withExpCheck(isCheckOptional);
        }

        @Override
        public MdocVerificationOpts build() {
            return new MdocVerificationOpts(
                    headerVerifiers,
                    contentVerifiers,
                    clientId,
                    oid4vpNonce,
                    mdocGeneratedNonce,
                    responseUri,
                    jwkThumbprint);
        }
    }
}
