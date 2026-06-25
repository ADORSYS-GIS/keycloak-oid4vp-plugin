package io.github.adorsysgis.keycloak.protocol.oid4vc.mdoc;

import com.authlete.mdoc.ValidityInfo;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.List;
import org.keycloak.common.VerificationException;
import org.keycloak.sdjwt.ClaimVerifier;
import org.keycloak.util.JsonSerialization;

/**
 * Options for mDoc device response verification.
 */
public class MdocVerificationOpts extends ClaimVerifier {

    public MdocVerificationOpts(
            List<Predicate<ObjectNode>> headerVerifiers, List<ClaimVerifier.Predicate<ObjectNode>> contentVerifiers) {
        super(headerVerifiers, contentVerifiers);
    }

    public void verifyValidityInfo(ValidityInfo validityInfo) throws VerificationException {
        var header = JsonSerialization.createObjectNode();
        var payload = JsonSerialization.createObjectNode();
        super.verifyClaims(header, payload);
    }

    public static MdocVerificationOpts.Builder builder() {
        return new MdocVerificationOpts.Builder();
    }

    public static class Builder extends ClaimVerifier.Builder {

        public Builder() {}

        public Builder(Integer clockSkew) {
            super(clockSkew);
        }

        @Override
        public MdocVerificationOpts.Builder withIatCheck(Integer allowedMaxAge) {
            return (MdocVerificationOpts.Builder) super.withIatCheck(allowedMaxAge);
        }

        @Override
        public MdocVerificationOpts.Builder withIatCheck(boolean isCheckOptional) {
            return (MdocVerificationOpts.Builder) super.withIatCheck(isCheckOptional);
        }

        @Override
        public MdocVerificationOpts.Builder withIatCheck(Integer allowedMaxAge, boolean isCheckOptional) {
            return (MdocVerificationOpts.Builder) super.withIatCheck(allowedMaxAge, isCheckOptional);
        }

        @Override
        public MdocVerificationOpts.Builder withNbfCheck() {
            return (MdocVerificationOpts.Builder) super.withNbfCheck();
        }

        @Override
        public MdocVerificationOpts.Builder withNbfCheck(boolean isCheckOptional) {
            return (MdocVerificationOpts.Builder) super.withNbfCheck(isCheckOptional);
        }

        @Override
        public MdocVerificationOpts.Builder withExpCheck() {
            return (MdocVerificationOpts.Builder) super.withExpCheck();
        }

        @Override
        public MdocVerificationOpts.Builder withExpCheck(boolean isCheckOptional) {
            return (MdocVerificationOpts.Builder) super.withExpCheck(isCheckOptional);
        }

        @Override
        public MdocVerificationOpts.Builder withClockSkew(int clockSkew) {
            return (MdocVerificationOpts.Builder) super.withClockSkew(clockSkew);
        }

        @Override
        public MdocVerificationOpts.Builder withContentVerifiers(
                List<ClaimVerifier.Predicate<ObjectNode>> contentVerifiers) {
            return (MdocVerificationOpts.Builder) super.withContentVerifiers(contentVerifiers);
        }

        @Override
        public MdocVerificationOpts.Builder addContentVerifiers(
                List<ClaimVerifier.Predicate<ObjectNode>> contentVerifiers) {
            return (MdocVerificationOpts.Builder) super.addContentVerifiers(contentVerifiers);
        }

        @Override
        public MdocVerificationOpts.Builder withAudCheck(String expectedAud) {
            return (MdocVerificationOpts.Builder) super.withAudCheck(expectedAud);
        }

        @Override
        public MdocVerificationOpts.Builder withClaimCheck(String claimName, String expectedValue) {
            return (MdocVerificationOpts.Builder) super.withClaimCheck(claimName, expectedValue);
        }

        @Override
        public MdocVerificationOpts.Builder withClaimCheck(
                String claimName, String expectedValue, boolean isOptionalCheck) {
            return (MdocVerificationOpts.Builder) super.withClaimCheck(claimName, expectedValue, isOptionalCheck);
        }

        public MdocVerificationOpts build() {
            return new MdocVerificationOpts(headerVerifiers, contentVerifiers);
        }
    }
}
