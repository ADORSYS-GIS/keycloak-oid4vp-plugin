package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

/**
 * Result of format-specific credential verification.
 *
 * @param identity the verified primary credential's origin, issuer, and subject; {@code null} for
 *     supporting credentials, session-bound presentations, or when no stable identity is exposed
 * @param claims verified credential claims
 */
public record VerifiedCredential(CredentialIdentity identity, JsonNode claims) {

    public VerifiedCredential {
        claims = Objects.requireNonNull(claims, "claims");
    }
}
