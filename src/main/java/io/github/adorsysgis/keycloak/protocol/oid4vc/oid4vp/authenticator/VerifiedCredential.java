package io.github.adorsysgis.keycloak.protocol.oid4vc.oid4vp.authenticator;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Objects;

/**
 * Result of format-specific credential verification.
 *
 * @param claims verified credential claims
 */
public record VerifiedCredential(JsonNode claims) {

    public VerifiedCredential {
        claims = Objects.requireNonNull(claims, "claims");
    }
}
