package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.TrustPolicy;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import org.keycloak.crypto.JavaAlgorithm;
import org.keycloak.jose.jws.crypto.HashUtils;
import org.keycloak.utils.StringUtil;

/**
 * Verified identity exposed by a credential: its cryptographically established origin, issuer
 * namespace, and subject. These values must come from information covered by successful credential
 * and trust verification. User resolution consumes the primary credential's identity; supporting
 * credentials do not define the authenticating user's identity.
 *
 * <p>Presentation-during-issuance credentials keep using the session-bound Keycloak user and carry
 * no external identity.
 */
public record CredentialIdentity(Origin origin, String issuer, String subject) {

    /** Cryptographically established origin of this verified identity. */
    public enum Origin {
        CURRENT_REALM,
        EXTERNAL;

        /**
         * Returns the origin established by the primary credential's successful trust policy.
         *
         * <p>Profile validation makes primary trust unambiguous: mDoc requires exactly one policy and
         * SD-JWT does not allow self trust to be combined with external trust. The credential verifier
         * has already validated the signature against the configured policy before this method is used.
         */
        public static Origin fromPrimaryTrust(CredentialRequirement credential) {
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

    /** Version prefix of {@link #externalId(String, String)}. Bump when the encoding changes. */
    public static final String EXTERNAL_ID_VERSION = "v1";

    public CredentialIdentity {
        Objects.requireNonNull(origin, "origin");
        if (StringUtil.isBlank(issuer)) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        if (StringUtil.isBlank(subject)) {
            throw new IllegalArgumentException("subject must not be blank");
        }
    }

    /**
     * Resolves the identity to expose on a {@link VerifiedCredential}.
     *
     * <p>Returns the primary identity when both the issuer namespace and the subject are available,
     * {@code null} otherwise. Supporting and session-bound credentials do not identify the
     * authenticating user. Verification itself never fails for a missing identity: existing trust
     * configurations (e.g. mdoc {@code x5c} anchors without an explicit issuer) keep authenticating
     * exactly as before. Callers that require an external identity, such as user import, must refuse
     * credentials that expose none.
     */
    public static CredentialIdentity forCredential(
            CredentialRequirement credentialReq, Origin origin, String issuer, String subject) {
        Objects.requireNonNull(credentialReq, "credentialReq");
        if (!credentialReq.isPrimary() || credentialReq.isSessionIdentity()) {
            return null;
        }
        if (StringUtil.isBlank(issuer) || StringUtil.isBlank(subject)) {
            return null;
        }
        return new CredentialIdentity(origin, issuer, subject);
    }

    /**
     * Creates the deterministic, versioned identifier stored in the federated identity link for an
     * external user. The encoding length-prefixes both values before hashing so {@code ("ab", "c")}
     * and {@code ("a", "bc")} never collide.
     */
    public static String externalId(String issuer, String subject) {
        if (StringUtil.isBlank(issuer)) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        if (StringUtil.isBlank(subject)) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        String framed =
                EXTERNAL_ID_VERSION + "|" + issuer.length() + "|" + issuer + "|" + subject.length() + "|" + subject;
        byte[] digest = HashUtils.hash(JavaAlgorithm.SHA256, framed.getBytes(StandardCharsets.UTF_8));
        return EXTERNAL_ID_VERSION + "." + HexFormat.of().formatHex(digest);
    }
}
