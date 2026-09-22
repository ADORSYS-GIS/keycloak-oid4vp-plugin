package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.profile.CredentialRequirement;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import org.keycloak.utils.StringUtil;

/**
 * Verified identity exposed by a credential: its cryptographically established origin, issuer
 * namespace, and subject. These values must come from information covered by successful credential
 * and trust verification. User resolution consumes the primary credential's identity; supporting
 * credentials may expose the same information for other verified-presentation processing.
 *
 * <p>Presentation-during-issuance credentials keep using the session-bound Keycloak user and carry
 * no external identity.
 */
public record CredentialIdentity(CredentialOrigin origin, String issuer, String subject) {

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
     * <p>Returns the identity when both the issuer namespace and the subject are available,
     * {@code null} otherwise. Verification itself never fails for a missing identity: existing
     * trust configurations (e.g. mdoc {@code x5c} anchors without an explicit issuer) keep
     * authenticating exactly as before. Callers that require an external identity, such as user
     * import, must refuse credentials that expose none.
     */
    public static CredentialIdentity forCredential(
            CredentialRequirement credentialReq, CredentialOrigin origin, String issuer, String subject) {
        Objects.requireNonNull(credentialReq, "credentialReq");
        if (credentialReq.isSessionIdentity()) {
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
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(framed.getBytes(StandardCharsets.UTF_8));
            return EXTERNAL_ID_VERSION + "." + HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required for external identity encoding", e);
        }
    }
}
