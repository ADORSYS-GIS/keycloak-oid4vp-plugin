package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

/**
 * Result of format-specific credential verification.
 *
 * @param issuer cryptographically verified Credential Issuer identifier, or {@code null} when the
 *     credential does not participate in credential-based user recovery
 * @param claims verified credential claims
 */
public record VerifiedCredential(String issuer, JsonNode claims) {

    public VerifiedCredential {
        claims = Objects.requireNonNull(claims, "claims");
    }
}
