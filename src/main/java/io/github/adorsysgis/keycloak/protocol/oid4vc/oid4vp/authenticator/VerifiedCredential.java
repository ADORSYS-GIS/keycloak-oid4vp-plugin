package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

/**
 * Result of format-specific credential verification.
 *
 * @param identity verified origin, issuer, and subject when the credential exposes a stable
 *     identity; {@code null} for session-bound presentations or credentials without one. User
 *     resolution uses only the primary credential's identity.
 * @param claims verified credential claims
 */
public record VerifiedCredential(CredentialIdentity identity, JsonNode claims) {

    public VerifiedCredential {
        claims = Objects.requireNonNull(claims, "claims");
    }
}
