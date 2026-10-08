package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.util.List;

/** Cryptographically established origin of a verified credential. */
public enum CredentialOrigin {
    CURRENT_REALM,
    EXTERNAL;

    /**
     * Returns the origin established by the primary credential's successful trust policy.
     *
     * <p>Profile validation makes primary trust unambiguous: mDoc requires exactly one policy and
     * SD-JWT does not allow self trust to be combined with external trust. The credential verifier
     * has already validated the signature against the configured policy before this method is used.
     */
    public static CredentialOrigin fromPrimaryTrust(CredentialRequirement credential) {
        if (!credential.isPrimary() || credential.isSessionIdentity()) {
            throw new IllegalArgumentException("Credential must be a non-session primary credential");
        }

        List<TrustPolicy> trust = credential.getTrust();
        if (trust == null || trust.isEmpty()) {
            return CURRENT_REALM;
        }

        boolean usesSelfTrust = trust.stream().anyMatch(policy -> TrustPolicy.SELF.equals(policy.getType()));
        boolean usesExternalTrust = trust.stream().anyMatch(policy -> !TrustPolicy.SELF.equals(policy.getType()));
        if (usesSelfTrust && usesExternalTrust) {
            throw new IllegalStateException(
                    "Primary credential must not combine self trust with external trust policies: "
                            + credential.getId());
        }
        return usesSelfTrust ? CURRENT_REALM : EXTERNAL;
    }
}
